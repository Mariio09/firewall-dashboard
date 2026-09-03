"""Tests de `app/firewall/runner.py`.

Contiene el test canonico numero 4 del proyecto: *un binario fuera de la
allowlist lanza `SecurityError`* (ver `Estrategia de tests` en la boveda).

Como se prueban estos tests, y por que asi: el runner se instancia apuntando a un
`iptables` FALSO, un script en `tmp_path` que registra su argv y su entorno en un
archivo. Es decir, **el runner ejecuta de verdad**. Con un mock de
`subprocess.run` se comprobaria que se le pasan los argumentos correctos, que es
justo lo que no queremos: `shell=False` y el entorno minimo son propiedades del
proceso hijo, y solo se demuestran mirando lo que el hijo vio.

De ahi que casi todas las afirmaciones se comprueben por EFECTO (el archivo de
registro, un testigo que no llega a crearse) y no por ausencia de excepcion, y
que cada afirmacion positiva venga con su contraprueba: que el bloqueo bloquea no
prueba nada si no se demuestra ademas que sin el bloqueo la operacion pasaba.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import structlog

from app.core.exceptions import FirewallCommandError, FirewallTimeoutError, SecurityError
from app.firewall import runner as runner_mod
from app.firewall.runner import SubprocessRunner

# Script que hace de iptables: vuelca su argv y su entorno en REGISTRO, escribe
# en las dos salidas y termina bien. `\n` literales: por eso el string es raw.
SCRIPT_REGISTRA = r"""#!/bin/sh
{ printf 'ARG:%s\n' "$@"; env | sed 's/^/ENV:/'; } > "REGISTRO"
printf 'salida estandar\n'
printf 'salida de error\n' >&2
exit 0
"""

# El fallo real medido en A2: exit 1, stdout vacio y el motivo por stderr.
SCRIPT_FALLA = r"""#!/bin/sh
printf 'iptables: No chain/target/match by that name.\n' >&2
exit 1
"""

SCRIPT_LENTO = r"""#!/bin/sh
sleep 3
"""

# sudo falso: exige `-n`, deja constancia y ejecuta el resto del argv.
SCRIPT_SUDO = r"""#!/bin/sh
printf 'SUDO:%s\n' "$@" > "REGISTRO"
[ "$1" = "-n" ] || exit 90
shift
exec "$@"
"""


def _script(destino: Path, cuerpo: str, registro: Path | None = None) -> Path:
    """Escribe un ejecutable de mentira y lo deja listo para lanzarse."""
    destino.write_text(cuerpo.replace("REGISTRO", str(registro or "")), encoding="utf-8")
    destino.chmod(0o755)
    return destino


@pytest.fixture(autouse=True)
def structlog_como_en_la_app() -> Iterator[None]:
    """Reproduce la configuracion global que deja `create_app()`, a proposito.

    `configure_logging` usa `cache_logger_on_first_use=True` y, con la
    configuracion de test, un logger filtrante a WARNING. Esa combinacion es la
    que hizo que el test del rastro pasara en solitario y fallara al correr la
    suite entera: el `.info` de un logger guardado en el modulo se congela como
    no-op en cuanto una prueba de integracion construye la aplicacion, y ya no se
    descongela. Dejar la condicion hostil puesta aqui es lo que impide que el
    fallo vuelva disfrazado de "en mi maquina pasa".
    """
    anterior = structlog.get_config()
    structlog.configure(
        processors=[structlog.processors.KeyValueRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
        cache_logger_on_first_use=True,
    )
    yield
    structlog.configure(**anterior)


@pytest.fixture
def logs_capturados() -> Iterator[list[dict[str, Any]]]:
    """Captura los eventos del runner con el nivel bajado a INFO.

    `capture_logs` sustituye los processors pero NO el `wrapper_class`, asi que
    sin bajar el nivel un evento INFO se descarta antes de llegar a la captura.
    """
    anterior = structlog.get_config()
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))
    with structlog.testing.capture_logs() as capturados:
        yield capturados
    structlog.configure(**anterior)


@pytest.fixture
def registro(tmp_path: Path) -> Path:
    """Donde el binario falso deja constancia de que se ejecuto."""
    return tmp_path / "registro.txt"


@pytest.fixture
def iptables_falso(tmp_path: Path, registro: Path) -> Path:
    return _script(tmp_path / "iptables", SCRIPT_REGISTRA, registro)


@pytest.fixture
def run_ok(iptables_falso: Path) -> SubprocessRunner:
    """Runner sin sudo apuntando al iptables falso. El caso base de casi todo."""
    return SubprocessRunner(use_sudo=False, iptables_bin=str(iptables_falso))


def _args_registrados(registro: Path) -> list[str]:
    lineas = registro.read_text(encoding="utf-8").splitlines()
    return [linea.removeprefix("ARG:") for linea in lineas if linea.startswith("ARG:")]


def _entorno_registrado(registro: Path) -> list[str]:
    lineas = registro.read_text(encoding="utf-8").splitlines()
    return [linea.removeprefix("ENV:") for linea in lineas if linea.startswith("ENV:")]


# --------------------------------------------------------------------------- #
# La allowlist. El test canonico y su contraprueba
# --------------------------------------------------------------------------- #


def test_binario_fuera_de_la_allowlist_lanza_securityerror(
    run_ok: SubprocessRunner, registro: Path
) -> None:
    """EL test de B2. Y ademas: no se ejecuta nada, ni siquiera se intenta."""
    with pytest.raises(SecurityError):
        run_ok.run(["rm", "-rf", "/"])
    assert not registro.exists(), "La validacion debe cortar ANTES de ejecutar nada"


def test_contraprueba_un_binario_de_la_allowlist_si_se_ejecuta(
    run_ok: SubprocessRunner, registro: Path
) -> None:
    """Sin esto, el test anterior podria estar pasando porque el runner no ejecuta nada."""
    resultado = run_ok.run(["iptables", "-S", "FWDASH_INPUT"])

    assert resultado.ok
    assert resultado.returncode == 0
    assert resultado.stdout == "salida estandar\n"
    assert registro.exists()
    assert _args_registrados(registro) == ["-S", "FWDASH_INPUT"]


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["/bin/sh", "-c", "echo hola"], id="ruta absoluta"),
        pytest.param(["../../bin/sh"], id="ruta relativa"),
        pytest.param(["sudo", "iptables", "-S"], id="sudo lo pone el runner, no el llamante"),
        pytest.param(["curl", "http://x"], id="binario cualquiera"),
        pytest.param([], id="argv vacio"),
    ],
)
def test_argv0_invalido_lanza_securityerror(
    run_ok: SubprocessRunner, registro: Path, argv: list[str]
) -> None:
    with pytest.raises(SecurityError):
        run_ok.run(argv)
    assert not registro.exists()


def test_una_cadena_no_es_un_argv(run_ok: SubprocessRunner, registro: Path) -> None:
    """Pasar `"iptables -S"` es el error que reintroduce la shell por la puerta de atras."""
    with pytest.raises(SecurityError):
        run_ok.run("iptables -S")  # type: ignore[arg-type]
    assert not registro.exists()


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["iptables", "--dport", 22], id="un entero colado"),
        pytest.param(["iptables", None], id="un None colado"),
        pytest.param(["iptables", "-s", "1.2.3.4\x00-j ACCEPT"], id="byte nulo"),
    ],
)
def test_argumento_que_no_es_una_cadena_limpia(
    run_ok: SubprocessRunner, registro: Path, argv: list
) -> None:
    with pytest.raises(SecurityError):
        run_ok.run(argv)
    assert not registro.exists()


def test_el_constructor_rechaza_un_binario_fuera_de_la_allowlist() -> None:
    """IPTABLES_BIN=/usr/bin/curl dejaria la allowlist en decoracion."""
    with pytest.raises(SecurityError):
        SubprocessRunner(iptables_bin="/usr/bin/curl")


def test_el_constructor_rechaza_una_ruta_relativa() -> None:
    with pytest.raises(SecurityError):
        SubprocessRunner(iptables_bin="iptables")


def test_los_hermanos_se_resuelven_en_el_mismo_directorio(
    tmp_path: Path, registro: Path, iptables_falso: Path
) -> None:
    """`iptables-save` se busca junto a `iptables`, no por PATH."""
    _script(tmp_path / "iptables-save", SCRIPT_REGISTRA, registro)
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(iptables_falso))

    resultado = corredor.run(["iptables-save", "-t", "filter"])

    assert resultado.argv[0] == str(tmp_path / "iptables-save")
    assert _args_registrados(registro) == ["-t", "filter"]


# --------------------------------------------------------------------------- #
# Sin shell no hay inyeccion
# --------------------------------------------------------------------------- #


def test_los_metacaracteres_llegan_literales(
    run_ok: SubprocessRunner, registro: Path, tmp_path: Path
) -> None:
    """El corazon del ejercicio: con `shell=False` el payload es un argumento mas."""
    testigo = tmp_path / "pwned"
    payload = f"; touch {testigo}; echo"

    run_ok.run(["iptables", "-m", "comment", "--comment", payload])

    assert payload in _args_registrados(registro), "El argumento debe llegar intacto"
    assert not testigo.exists(), "Si esto existe, algo interpreto el argumento como shell"


def test_las_comillas_y_el_salto_de_linea_tampoco_parten_el_argumento(
    run_ok: SubprocessRunner, registro: Path
) -> None:
    payload = "un 'comentario'\ncon $(id) dentro"

    run_ok.run(["iptables", "--comment", payload])

    # El registro separa argumentos por lineas, asi que un payload con salto de
    # linea se comprueba sobre el texto completo.
    assert payload in registro.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Entorno minimo
# --------------------------------------------------------------------------- #


def test_el_hijo_no_hereda_el_entorno_del_padre(
    run_ok: SubprocessRunner, registro: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECRETO_DEL_PADRE", "no-deberia-viajar")

    run_ok.run(["iptables", "-S"])

    entorno = _entorno_registrado(registro)
    assert entorno, "El script falso deberia haber volcado su entorno"
    assert not [linea for linea in entorno if linea.startswith("SECRETO_DEL_PADRE=")]
    assert "LC_ALL=C" in entorno, "El parser depende de un locale fijo"
    assert f"PATH={runner_mod.SAFE_ENV['PATH']}" in entorno


# --------------------------------------------------------------------------- #
# Fallos: codigo de salida, timeout y binario que no se puede ejecutar
# --------------------------------------------------------------------------- #


def test_codigo_de_salida_no_cero_lanza_firewallcommanderror(tmp_path: Path) -> None:
    falso = _script(tmp_path / "iptables", SCRIPT_FALLA)
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(falso))

    with pytest.raises(FirewallCommandError) as exc:
        corredor.run(["iptables", "-S", "FWDASH_NOEXISTE"])

    assert exc.value.details == {"returncode": 1}
    assert "No chain" not in exc.value.message, "El stderr crudo va al log, no al cliente"


def test_con_check_false_el_fallo_se_devuelve_en_vez_de_lanzarse(tmp_path: Path) -> None:
    """Lo que necesita `ensure_scaffold`: preguntar sin que el error sea excepcion."""
    falso = _script(tmp_path / "iptables", SCRIPT_FALLA)
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(falso))

    resultado = corredor.run(["iptables", "-S", "FWDASH_NOEXISTE"], check=False)

    assert not resultado.ok
    assert resultado.returncode == 1
    assert resultado.stdout == "", "iptables informa del error por stderr, no por stdout"
    assert "No chain/target/match by that name." in resultado.stderr


def test_el_timeout_lanza_firewalltimeouterror(tmp_path: Path) -> None:
    lento = _script(tmp_path / "iptables", SCRIPT_LENTO)
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(lento))

    with pytest.raises(FirewallTimeoutError) as exc:
        corredor.run(["iptables", "-S"], timeout=0.3)

    assert exc.value.details == {"timeout_seconds": 0.3}
    assert exc.value.http_status == 504


def test_contraprueba_un_comando_rapido_no_agota_el_mismo_timeout(
    run_ok: SubprocessRunner,
) -> None:
    """Si no, el test anterior podria estar pasando por un timeout imposible de cumplir."""
    resultado = run_ok.run(["iptables", "-S"], timeout=0.3)
    assert resultado.ok


@pytest.mark.parametrize("timeout", [0, -1.0, math.nan, math.inf])
def test_un_timeout_invalido_es_un_error_de_programacion(
    run_ok: SubprocessRunner, registro: Path, timeout: float
) -> None:
    with pytest.raises(ValueError):
        run_ok.run(["iptables", "-S"], timeout=timeout)
    assert not registro.exists()


def test_un_binario_que_no_existe_no_escapa_como_filenotfounderror(tmp_path: Path) -> None:
    """La capa de dominio no debe ver excepciones crudas de la stdlib."""
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(tmp_path / "vacio" / "iptables"))

    with pytest.raises(FirewallCommandError):
        corredor.run(["iptables", "-S"])


def test_un_binario_sin_permiso_de_ejecucion_tampoco(tmp_path: Path, registro: Path) -> None:
    falso = _script(tmp_path / "iptables", SCRIPT_REGISTRA, registro)
    falso.chmod(0o644)
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(falso))

    with pytest.raises(FirewallCommandError):
        corredor.run(["iptables", "-S"])
    assert not registro.exists()


# --------------------------------------------------------------------------- #
# sudo
# --------------------------------------------------------------------------- #


def test_con_use_sudo_el_comando_pasa_por_sudo_n(
    tmp_path: Path,
    registro: Path,
    iptables_falso: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registro_sudo = tmp_path / "registro_sudo.txt"
    sudo_falso = _script(tmp_path / "sudo", SCRIPT_SUDO, registro_sudo)
    monkeypatch.setattr(runner_mod, "SUDO_BIN", str(sudo_falso))
    corredor = SubprocessRunner(use_sudo=True, iptables_bin=str(iptables_falso))

    resultado = corredor.run(["iptables", "-S"])

    assert resultado.argv[:2] == (str(sudo_falso), "-n"), "`-n`: nunca esperar una contraseña"
    assert registro_sudo.exists(), "sudo tiene que haberse ejecutado de verdad"
    assert registro.exists(), "y tiene que haber acabado ejecutando iptables"
    assert _args_registrados(registro) == ["-S"]


def test_contraprueba_sin_use_sudo_no_aparece_sudo(
    tmp_path: Path, iptables_falso: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registro_sudo = tmp_path / "registro_sudo.txt"
    sudo_falso = _script(tmp_path / "sudo", SCRIPT_SUDO, registro_sudo)
    monkeypatch.setattr(runner_mod, "SUDO_BIN", str(sudo_falso))
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(iptables_falso))

    resultado = corredor.run(["iptables", "-S"])

    assert resultado.argv[0] == str(iptables_falso)
    assert not registro_sudo.exists()


# --------------------------------------------------------------------------- #
# El resultado y la traza
# --------------------------------------------------------------------------- #


def test_el_resultado_separa_las_dos_salidas_y_mide_el_tiempo(
    run_ok: SubprocessRunner, iptables_falso: Path
) -> None:
    resultado = run_ok.run(["iptables", "-S"])

    assert resultado.stdout == "salida estandar\n"
    assert resultado.stderr == "salida de error\n"
    assert resultado.argv == (str(iptables_falso), "-S")
    assert resultado.duration_ms > 0


def test_el_argv_se_registra_antes_de_ejecutar(
    tmp_path: Path, logs_capturados: list[dict[str, Any]]
) -> None:
    """Si el proceso muere, la traza de lo que se iba a ejecutar ya tiene que estar.

    Se comprueba con un comando que NO llega a completarse: el binario no existe,
    asi que el unico modo de que el evento `start` aparezca es que se emitiera
    antes de intentar la ejecucion.
    """
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(tmp_path / "vacio" / "iptables"))

    with pytest.raises(FirewallCommandError):
        corredor.run(["iptables", "-S", "FWDASH_INPUT"])

    eventos = [linea["event"] for linea in logs_capturados]
    assert eventos[0] == "firewall.command.start"
    assert logs_capturados[0]["argv"] == [
        str(tmp_path / "vacio" / "iptables"),
        "-S",
        "FWDASH_INPUT",
    ]
    assert "firewall.command.no_ejecutable" in eventos


def test_el_stderr_de_un_fallo_va_al_log(
    tmp_path: Path, logs_capturados: list[dict[str, Any]]
) -> None:
    falso = _script(tmp_path / "iptables", SCRIPT_FALLA)
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(falso))

    with pytest.raises(FirewallCommandError):
        corredor.run(["iptables", "-S"])

    fallos = [linea for linea in logs_capturados if linea["event"] == "firewall.command.failed"]
    assert len(fallos) == 1
    assert "No chain/target/match by that name." in fallos[0]["stderr"]
    assert fallos[0]["returncode"] == 1


def test_con_el_nivel_en_warning_el_rastro_previo_desaparece(tmp_path: Path) -> None:
    """Comportamiento real, no deseado: el rastro `start` se emite a nivel INFO.

    Con `LOG_LEVEL=WARNING` en el despliegue, la traza de QUE se iba a ejecutar no
    llega a emitirse; solo sobrevive la del fallo. La fixture de este modulo deja
    puesto justo ese nivel, asi que el test fija por escrito el comportamiento
    para que la decision —subir el rastro de nivel o exigir INFO en la VM— se tome
    a la vista y no por descuido. Ver `Deuda tecnica` en la boveda.
    """
    falso = _script(tmp_path / "iptables", SCRIPT_FALLA)
    corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(falso))

    with structlog.testing.capture_logs() as capturados, pytest.raises(FirewallCommandError):
        corredor.run(["iptables", "-S"])

    eventos = [linea["event"] for linea in capturados]
    assert "firewall.command.start" not in eventos
    assert "firewall.command.failed" in eventos
