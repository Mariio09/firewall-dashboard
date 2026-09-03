"""El unico punto del proyecto que ejecuta procesos externos.

Bloque B2. Si `subprocess` aparece en cualquier otro archivo, es un bug de
seguridad, no de estilo (lo vigila `tests/unit/test_architecture.py`).

Defensa en profundidad (docs/SECURITY.md):
  1. `shell=False` SIEMPRE. Es el valor por defecto de `subprocess.run`, pero se
     deja explicito porque es el punto entero del ejercicio: sin shell no hay
     interpretacion de `;`, `|`, `$()` ni comillas, asi que la inyeccion de
     comandos deja de ser posible por construccion.
  2. Allowlist de binarios. Un argv cuyo ejecutable no este en `ALLOWED_BINARIES`
     lanza `SecurityError` antes de llegar al sistema.
  3. Argumentos siempre en lista, nunca concatenando strings.
  4. Entorno minimo y `LC_ALL=C`, para que el parser no dependa del locale de la
     VM y no se hereden variables del proceso padre.
  5. Timeout obligatorio: un `iptables` esperando el lock del xtables bloquea el
     worker indefinidamente.
  6. Log estructurado del argv completo ANTES de ejecutar.

Reparto de responsabilidades con el resto del paquete: el `renderer` emite
`argv[0]` como el NOMBRE LOGICO (`iptables`), nunca una ruta. Traducir ese nombre
a un ejecutable real y decidir si delante va `sudo` es trabajo de este modulo, y
de nadie mas. Esa frontera es lo que hace que la allowlist sirva de algo: se
comprueba sobre un nombre corto, cerrado y sin barras, no sobre una ruta que
podria venir de cualquier sitio.
"""

from __future__ import annotations

import math
import subprocess  # nosec B404 - este modulo existe precisamente para contenerlo
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import structlog

from app.core.exceptions import FirewallCommandError, FirewallTimeoutError, SecurityError

DEFAULT_TIMEOUT_SECONDS = 10.0

#: Ruta absoluta de `sudo`. No se busca en el PATH a proposito: resolver por PATH
#: es justo el secuestro que `SAFE_ENV` intenta evitar.
SUDO_BIN = "/usr/bin/sudo"

#: Entorno minimo. `LC_ALL=C` fija el formato de salida de iptables.
SAFE_ENV: dict[str, str] = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}

#: Unicos ejecutables que este proyecto puede invocar, jamas ampliar sin ADR.
ALLOWED_BINARIES: frozenset[str] = frozenset(
    {"iptables", "ip6tables", "iptables-save", "iptables-restore"}
)

#: Recorte del stderr que va al log. Un `iptables-restore` que falla puede
#: escupir el ruleset entero, y un log ilegible no se lee.
MAX_STDERR_LOG_CHARS = 2000


def _log() -> Any:
    """El logger se pide en CADA llamada; no se guarda uno en el modulo.

    `configure_logging` configura structlog con `cache_logger_on_first_use=True`,
    y un proxy de modulo congela su binding la primera vez que se usa. Si esa
    primera vez ocurre antes de que la aplicacion configure el logging —el import
    del modulo pasa mucho antes que `create_app()`—, el logger se queda cacheado
    con la configuracion por defecto: sin el renderer JSON y, peor, **sin el
    processor que censura los valores sensibles**. Y si el nivel configurado era
    WARNING, `.info` se congela como no-op para el resto del proceso.

    Pedirlo aqui cuesta lo que cuesta construir un proxy, cuatro ordenes de
    magnitud menos que lanzar el subproceso que viene detras.
    """
    return structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Lo que devolvio un comando. `argv` es el REAL, ya resuelto.

    Es decir: con la ruta absoluta del binario y con `sudo` delante si lo hubo.
    Es lo que de verdad se ejecuto, que es lo unico que sirve para auditar. No
    debe viajar al cliente: contiene rutas del sistema (ver `AppError.details`).

    `stdout` y `stderr` van separados porque iptables informa de los errores por
    stderr dejando stdout vacio, y mezclarlos haria imposible distinguir una
    salida legitima de un fallo.
    """

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner(Protocol):
    """Costura de test mas interna.

    Inyectando un runner falso que devuelve stdout enlatado se puede verificar que
    `IptablesBackend` construye el argv correcto y que el parser lee bien salidas
    reales, todo sin ejecutar nada. Ver docs/ARCHITECTURE.md §3.4.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        check: bool = True,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Implementacion real. Solo se instancia dentro de la VM.

    `iptables_bin` es la ruta del binario de iptables; el resto de la allowlist se
    resuelve como HERMANOS suyos en el mismo directorio (`iptables-save` junto a
    `iptables`). Asi hay un unico parametro de configuracion en vez de cuatro, y
    no existe forma de que una variable de entorno apunte cada nombre logico a un
    ejecutable distinto.

    `use_sudo` solo tiene sentido lanzando el backend A MANO como `fwdash`. Bajo
    la unidad de systemd va en `false`: `NoNewPrivileges=yes` anula el setuid de
    `sudo`, y quien concede el privilegio es `AmbientCapabilities`
    (ADR-0003, y la nota `Privilegios del servicio` de la boveda).
    """

    def __init__(self, *, use_sudo: bool = True, iptables_bin: str = "/usr/sbin/iptables") -> None:
        ruta = Path(iptables_bin)
        if not ruta.is_absolute():
            raise SecurityError(
                f"El binario de iptables debe configurarse con ruta absoluta: {iptables_bin!r}"
            )
        if ruta.name not in ALLOWED_BINARIES:
            # Sin esta comprobacion, un IPTABLES_BIN=/usr/bin/curl en el .env
            # convertiria la allowlist en decoracion: el nombre logico seguiria
            # siendo "iptables" y el ejecutable seria otra cosa.
            raise SecurityError(f"Binario de iptables fuera de la allowlist: {iptables_bin!r}")
        self._use_sudo = use_sudo
        self._iptables_bin = ruta

    # ----------------------------------------------------------------- #
    # Validacion: todo lo que sigue ocurre ANTES de tocar el sistema
    # ----------------------------------------------------------------- #

    def _validar(self, argv: Sequence[str]) -> list[str]:
        """Comprueba el argv y devuelve una copia propia, o lanza `SecurityError`.

        La copia importa: si el llamante mutara la lista despues de la validacion,
        se ejecutaria algo distinto de lo validado.
        """
        if isinstance(argv, str | bytes):
            # Una cadena TAMBIEN es una secuencia, y `subprocess` la trataria como
            # el comando entero. Es el error que reintroduce la shell por la
            # puerta de atras, asi que se corta explicitamente.
            raise SecurityError("El comando debe ser una lista de argumentos, no una cadena.")

        partes = list(argv)
        if not partes:
            raise SecurityError("El comando esta vacio.")

        for i, elemento in enumerate(partes):
            if not isinstance(elemento, str):
                raise SecurityError(
                    f"Argumento {i} no es una cadena: {type(elemento).__name__}. "
                    "Los argumentos se pasan ya convertidos, nunca `None` ni enteros."
                )
            if "\x00" in elemento:
                raise SecurityError(f"Argumento {i} contiene un byte nulo.")

        nombre = partes[0]
        if "/" in nombre:
            raise SecurityError(
                f"argv[0] debe ser un nombre logico, no una ruta: {nombre!r}. "
                "Quien resuelve la ruta es el runner."
            )
        if nombre not in ALLOWED_BINARIES:
            # Aqui caen tanto `rm` como `sudo`: construir el prefijo de sudo es
            # trabajo del runner, y un llamante que lo intente es un bug.
            raise SecurityError(f"Binario fuera de la allowlist: {nombre!r}")

        return partes

    def _resolver(self, nombre: str) -> str:
        """Nombre logico -> ruta absoluta, hermana del binario configurado."""
        return str(self._iptables_bin.with_name(nombre))

    # ----------------------------------------------------------------- #
    # Ejecucion
    # ----------------------------------------------------------------- #

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        check: bool = True,
    ) -> CommandResult:
        """Ejecuta un comando de la allowlist y devuelve su resultado.

        Con `check=True` (por defecto) un codigo de salida distinto de cero lanza
        `FirewallCommandError`. Con `check=False` se devuelve el resultado tal
        cual: es lo que necesita `ensure_scaffold` para preguntar si una cadena
        existe, porque el error de iptables es ambiguo y no se puede clasificar
        por su texto (ver la nota `CommandRunner y subprocess`).
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError(f"El timeout debe ser un numero positivo y finito: {timeout!r}")

        partes = self._validar(argv)
        real = [self._resolver(partes[0]), *partes[1:]]
        if self._use_sudo:
            # `-n`: si sudo necesitara contraseña, falla en el acto en vez de
            # quedarse esperando en un stdin que nadie va a rellenar.
            real = [SUDO_BIN, "-n", *real]

        # El log va ANTES de ejecutar: si el proceso muere, la traza de lo que se
        # iba a ejecutar ya esta escrita.
        _log().info("firewall.command.start", argv=real, timeout_s=timeout)
        inicio = time.monotonic()

        try:
            completado = subprocess.run(  # nosec B603 - argv validado y sin shell
                real,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=dict(SAFE_ENV),
                timeout=timeout,
                check=False,
                cwd="/",
                # El hijo no comparte grupo de proceso: un Ctrl-C en la terminal
                # del padre no llega a iptables a mitad de una escritura.
                start_new_session=True,
            )
        except subprocess.TimeoutExpired as exc:
            _log().error(
                "firewall.command.timeout",
                argv=real,
                timeout_s=timeout,
                duration_ms=_ms(inicio),
            )
            # `details` no lleva ni argv ni rutas: llega tal cual al cliente.
            raise FirewallTimeoutError(details={"timeout_seconds": timeout}) from exc
        except OSError as exc:
            # Binario inexistente, sin permiso de ejecucion, ETXTBSY... Es un
            # fallo del sistema, no del usuario, y el detalle se queda en el log.
            _log().error("firewall.command.no_ejecutable", argv=real, error=str(exc))
            raise FirewallCommandError("No se ha podido ejecutar el comando del firewall.") from exc

        resultado = CommandResult(
            argv=tuple(real),
            returncode=completado.returncode,
            stdout=completado.stdout,
            stderr=completado.stderr,
            duration_ms=_ms(inicio),
        )

        if resultado.ok:
            _log().info(
                "firewall.command.done",
                argv=real,
                returncode=resultado.returncode,
                duration_ms=resultado.duration_ms,
            )
        else:
            _log().warning(
                "firewall.command.failed",
                argv=real,
                returncode=resultado.returncode,
                duration_ms=resultado.duration_ms,
                stderr=resultado.stderr[:MAX_STDERR_LOG_CHARS],
            )
            if check:
                raise FirewallCommandError(details={"returncode": resultado.returncode})

        return resultado


def _ms(inicio: float) -> float:
    """Milisegundos transcurridos, redondeados. `monotonic` no salta con la hora."""
    return round((time.monotonic() - inicio) * 1000, 3)
