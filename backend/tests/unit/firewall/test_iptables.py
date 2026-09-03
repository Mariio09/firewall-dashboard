"""Tests de `app/firewall/iptables.py` (bloque B3).

Aqui no se ejecuta iptables. Se inyecta un `CommandRunner` falso que **modela el
sistema**: sabe que cadenas existen, que saltos hay puestos, y cambia de estado
cuando le llega un `-N`, un `-I`, un `-D` o un `-X`. Es mas trabajo que grabar
llamadas, y es la unica forma de comprobar EFECTOS en vez de ausencia de error
(la leccion de A5, cobrada cara en B0): que `teardown` deja el sistema limpio se
demuestra mirando el sistema, no viendo que no salto ninguna excepcion.

Y cada afirmacion positiva con su contraprueba (la mitad que añadio B1): que
`ensure_scaffold` no escriba nada la segunda vez no prueba nada si no se
demuestra que la primera SI escribio.

La otra costura -- que el argv llegue intacto al proceso hijo, sin shell y con el
entorno minimo -- es de `SubprocessRunner` y se prueba en `test_runner.py` contra
un binario falso de verdad. Aqui se prueba lo de arriba: que el argv es el
correcto y que la salida se lee bien.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from app.core.exceptions import FirewallCommandError, InvalidRuleError
from app.firewall.base import FirewallBackend
from app.firewall.iptables import MAX_SALTOS_DUPLICADOS, IptablesBackend
from app.firewall.runner import CommandResult
from app.firewall.spec import Action, Chain, Protocol, RuleSpec

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "iptables_output"
UUID_A = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
CADENAS = ("FWDASH_INPUT", "FWDASH_OUTPUT", "FWDASH_FORWARD")
SALTOS = (("INPUT", "FWDASH_INPUT"), ("OUTPUT", "FWDASH_OUTPUT"), ("FORWARD", "FWDASH_FORWARD"))


# --------------------------------------------------------------------------- #
# El doble: un iptables de mentira con estado
# --------------------------------------------------------------------------- #


class SistemaFalso:
    """Modelo minimo de iptables. Cumple el Protocol `CommandRunner`.

    Solo entiende los subcomandos que este backend usa. Cualquier otro es un
    fallo del test, no del codigo: si el backend empieza a emitir algo nuevo,
    aqui explota en vez de pasar en verde silenciosamente.
    """

    def __init__(
        self,
        *,
        cadenas: Sequence[str] = (),
        saltos: Sequence[tuple[str, str]] = (),
        salidas: dict[str, str] | None = None,
        romper_en: str | None = None,
    ) -> None:
        self.cadenas: set[str] = set(cadenas)
        self.saltos: list[tuple[str, str]] = list(saltos)
        self.reglas: dict[str, list[list[str]]] = {c: [] for c in cadenas}
        self.salidas: dict[str, str] = salidas or {}
        #: Marca que, si aparece en un argv, hace fallar ese comando. Sirve para
        #: comprobar que pasa cuando iptables dice que no a mitad de camino.
        self.romper_en = romper_en
        self.vistos: list[list[str]] = []
        self.timeouts: list[float] = []

    # -- Protocol ----------------------------------------------------------- #

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 10.0,
        check: bool = True,
    ) -> CommandResult:
        partes = list(argv)
        self.vistos.append(partes)
        self.timeouts.append(timeout)
        if self.romper_en is not None and self.romper_en in partes:
            codigo, salida = 1, ""
        else:
            codigo, salida = self._ejecutar(partes)
        if codigo != 0 and check:
            raise FirewallCommandError(details={"returncode": codigo})
        return CommandResult(tuple(partes), codigo, salida, "", 0.0)

    # -- El "kernel" -------------------------------------------------------- #

    def _ejecutar(self, argv: list[str]) -> tuple[int, str]:
        orden = argv[1]

        if orden == "-N":
            if argv[2] in self.cadenas:
                return 1, ""
            self.cadenas.add(argv[2])
            self.reglas[argv[2]] = []
            return 0, ""

        if orden == "-X":
            if argv[2] not in self.cadenas:
                return 1, ""
            if any(destino == argv[2] for _, destino in self.saltos):
                # iptables se niega a borrar una cadena con referencias. Es lo
                # que convierte el orden de `teardown` en obligatorio.
                return 1, ""
            self.cadenas.discard(argv[2])
            self.reglas.pop(argv[2], None)
            return 0, ""

        if orden == "-F":
            if argv[2] not in self.cadenas:
                return 1, ""
            self.reglas[argv[2]] = []
            return 0, ""

        if orden == "-A":
            if argv[2] not in self.cadenas:
                return 1, ""
            self.reglas[argv[2]].append(argv[3:])
            return 0, ""

        if orden == "-C":
            return (0, "") if (argv[2], argv[4]) in self.saltos else (1, "")

        if orden == "-I":
            self.saltos.insert(0, (argv[2], argv[5]))
            return 0, ""

        if orden == "-D":
            par = (argv[2], argv[4])
            if par not in self.saltos:
                return 1, ""
            self.saltos.remove(par)
            return 0, ""

        if orden == "-S":
            if argv[2] not in self.cadenas:
                return 1, ""
            return 0, self.salidas.get("-S", "")

        if orden == "-L":
            if argv[2] not in self.cadenas:
                return 1, ""
            return 0, self.salidas.get("-L", "")

        raise AssertionError(f"El backend emitio un subcomando que este doble no modela: {argv}")


def montado(**kwargs: Any) -> SistemaFalso:
    """Sistema con el andamiaje ya puesto, que es el estado normal."""
    return SistemaFalso(cadenas=CADENAS, saltos=SALTOS, **kwargs)


def regla(ip: str = "10.0.0.5", *, uuid: str | None = None) -> RuleSpec:
    return RuleSpec(
        chain=Chain.INPUT,
        action=Action.DROP,
        protocol=Protocol.TCP,
        src_ip=ip,
        dst_port="3306",
        rule_uuid=uuid,
    )


def escrituras(sistema: SistemaFalso) -> list[list[str]]:
    """Los comandos que MODIFICAN. Los sondeos (`-L`, `-C`, `-S`) no cuentan."""
    return [a for a in sistema.vistos if a[1] in ("-N", "-X", "-F", "-A", "-I", "-D")]


# --------------------------------------------------------------------------- #
# El contrato
# --------------------------------------------------------------------------- #


def test_cumple_el_protocol_firewallbackend() -> None:
    assert isinstance(IptablesBackend(montado()), FirewallBackend)


def test_una_tabla_que_no_es_filter_se_rechaza_en_el_constructor() -> None:
    """Este backend no emite `-t`, asi que aceptar otra tabla seria mentir."""
    with pytest.raises(InvalidRuleError):
        IptablesBackend(montado(), table="nat")


def test_un_prefijo_de_cadena_invalido_falla_como_en_el_fake() -> None:
    with pytest.raises(InvalidRuleError):
        IptablesBackend(montado(), chain_prefix="fwdash minusculas").read_ruleset(Chain.INPUT)


def test_el_backend_real_no_guarda_estado() -> None:
    """Es apatrida: cada lectura vuelve a preguntarle al sistema.

    De ahi que compartir una sola instancia entre peticiones no le cambie nada,
    al contrario que al fake, que guarda las cadenas en memoria.
    """
    sistema = montado(salidas={"-S": "-A FWDASH_INPUT -j DROP\n"})
    backend = IptablesBackend(sistema)
    backend.read_ruleset(Chain.INPUT)
    backend.read_ruleset(Chain.INPUT)
    assert [a for a in sistema.vistos if a[1] == "-S"] == [["iptables", "-S", "FWDASH_INPUT"]] * 2


# --------------------------------------------------------------------------- #
# ensure_scaffold
# --------------------------------------------------------------------------- #


def test_ensure_scaffold_monta_cadenas_y_saltos_sobre_un_sistema_virgen() -> None:
    sistema = SistemaFalso()
    IptablesBackend(sistema).ensure_scaffold()

    assert sistema.cadenas == set(CADENAS)
    assert sorted(sistema.saltos) == sorted(SALTOS)


def test_el_salto_se_inserta_en_la_posicion_1() -> None:
    """La politica de la app tiene que evaluarse antes que lo que ya hubiera.

    Con `-A` en vez de `-I 1`, un `DROP` previo del sistema se comeria el
    paquete antes de llegar a la cadena gestionada y ninguna regla del dashboard
    tendria efecto. Es un bug que no da error: solo deja de filtrar.
    """
    sistema = SistemaFalso()
    IptablesBackend(sistema).ensure_scaffold()

    insertados = [a for a in sistema.vistos if a[1] == "-I"]
    assert insertados == [
        ["iptables", "-I", "INPUT", "1", "-j", "FWDASH_INPUT"],
        ["iptables", "-I", "OUTPUT", "1", "-j", "FWDASH_OUTPUT"],
        ["iptables", "-I", "FORWARD", "1", "-j", "FWDASH_FORWARD"],
    ]


def test_ensure_scaffold_es_idempotente() -> None:
    """Segunda llamada: ni una escritura. Con su contraprueba."""
    virgen = SistemaFalso()
    IptablesBackend(virgen).ensure_scaffold()
    assert len(escrituras(virgen)) == 6, "contraprueba: la primera vez SI escribe"

    ya_montado = montado()
    IptablesBackend(ya_montado).ensure_scaffold()
    assert escrituras(ya_montado) == []


def test_ensure_scaffold_repone_solo_el_salto_que_falta() -> None:
    """Estado real tras un `teardown` a medias, o tras un `iptables -F INPUT`.

    La cadena sigue ahi con sus reglas y lo que se ha perdido es el salto. Volver
    a crear la cadena fallaria; no reponer el salto dejaria un firewall que no
    filtra nada y no se queja.
    """
    sistema = montado()
    sistema.saltos.remove(("INPUT", "FWDASH_INPUT"))

    IptablesBackend(sistema).ensure_scaffold()

    assert escrituras(sistema) == [["iptables", "-I", "INPUT", "1", "-j", "FWDASH_INPUT"]]
    assert ("INPUT", "FWDASH_INPUT") in sistema.saltos


def test_ensure_scaffold_no_se_traga_los_errores() -> None:
    """Idempotente por PREGUNTA, no por tolerancia al fallo.

    Si se implementara lanzando `-N` y ignorando el error, un `-N` que falla por
    falta de privilegios seria indistinguible de "la cadena ya estaba" -- y el
    servicio arrancaria tan contento sin firewall ninguno.
    """
    sistema = SistemaFalso(romper_en="-N")
    with pytest.raises(FirewallCommandError):
        IptablesBackend(sistema).ensure_scaffold()


# --------------------------------------------------------------------------- #
# apply_ruleset
# --------------------------------------------------------------------------- #


def test_aplicar_vacia_y_reconstruye_en_orden() -> None:
    sistema = montado()
    IptablesBackend(sistema).apply_ruleset(Chain.INPUT, [regla()])

    emitidos = escrituras(sistema)
    assert emitidos[0] == ["iptables", "-F", "FWDASH_INPUT"]
    assert all("fwdash:guardian" in " ".join(a) for a in emitidos[1:4])
    assert emitidos[-1][-1] == Action.DROP.value
    assert len(emitidos) == 5


def test_aplicar_dos_veces_deja_solo_lo_ultimo() -> None:
    """No hay add ni delete: el estado final solo depende de las specs."""
    sistema = montado()
    backend = IptablesBackend(sistema)
    backend.apply_ruleset(Chain.INPUT, [regla("1.2.3.4"), regla("5.6.7.8")])
    backend.apply_ruleset(Chain.INPUT, [regla("9.9.9.9")])

    aplicadas = [" ".join(r) for r in sistema.reglas["FWDASH_INPUT"]]
    assert sum(1 for r in aplicadas if "9.9.9.9/32" in r) == 1
    assert not any("1.2.3.4/32" in r or "5.6.7.8/32" in r for r in aplicadas)


def test_los_comandos_devueltos_son_los_que_se_ejecutaron() -> None:
    """`commands` alimenta el preview: si divergiera, el preview mentiria."""
    sistema = montado()
    resultado = IptablesBackend(sistema).apply_ruleset(Chain.INPUT, [regla()])

    assert [list(c) for c in resultado.commands] == escrituras(sistema)
    assert resultado.applied == 1, "cuenta specs, no comandos"


def test_el_dry_run_no_ejecuta_nada_y_devuelve_lo_mismo() -> None:
    real, seco = montado(), montado()
    esperado = IptablesBackend(real).apply_ruleset(Chain.INPUT, [regla()])
    preview = IptablesBackend(seco).apply_ruleset(Chain.INPUT, [regla()], dry_run=True)

    assert escrituras(seco) == []
    assert preview.commands == esperado.commands
    assert preview.dry_run and not esperado.dry_run


def test_el_dry_run_tambien_exige_que_la_cadena_exista() -> None:
    """Un preview de comandos que no se podrian ejecutar es una mentira.

    Y ademas el fake falla en este caso: dos backends que responden distinto a lo
    mismo son justo el riesgo de docs/ARCHITECTURE.md §8.
    """
    with pytest.raises(FirewallCommandError) as error:
        IptablesBackend(SistemaFalso()).apply_ruleset(Chain.INPUT, [regla()], dry_run=True)
    assert error.value.details == {"chain": "FWDASH_INPUT"}


def test_una_spec_de_otra_cadena_no_llega_a_vaciar_nada() -> None:
    """Se renderiza entero ANTES de ejecutar: el fallo no deja la cadena a medias."""
    sistema = montado()
    with pytest.raises(InvalidRuleError):
        IptablesBackend(sistema).apply_ruleset(
            Chain.INPUT, [RuleSpec(chain=Chain.OUTPUT, action=Action.ACCEPT)]
        )
    assert sistema.vistos and escrituras(sistema) == []


def test_si_falla_a_mitad_los_guardianes_ya_estan_puestos() -> None:
    """El invariante de seguridad de una aplicacion sin transaccion.

    No hay rollback: el primer comando que falla aborta el resto y la cadena
    queda con menos reglas de las pedidas. Es seguro porque el renderer emite el
    `-F` y ACTO SEGUIDO los guardianes, asi que lo que se pierde son reglas de
    usuario, nunca el acceso a la VM ni a la API.
    """
    sistema = montado(romper_en="3306")
    with pytest.raises(FirewallCommandError):
        IptablesBackend(sistema).apply_ruleset(Chain.INPUT, [regla()])

    puestas = [" ".join(r) for r in sistema.reglas["FWDASH_INPUT"]]
    assert len(puestas) == 3
    assert all("fwdash:guardian" in r for r in puestas)


def test_los_parametros_de_gestion_salen_del_constructor() -> None:
    """Un backend configurado distinto que el `.env` cerraria el acceso a la API."""
    sistema = montado()
    IptablesBackend(sistema, management_port=8080, management_cidr="10.9.0.0/16").apply_ruleset(
        Chain.INPUT, []
    )
    guardian = next(a for a in escrituras(sistema) if "guardian:management" in " ".join(a))
    assert "8080" in guardian and "10.9.0.0/16" in guardian


def test_el_prefijo_de_cadena_del_constructor_llega_al_argv() -> None:
    sistema = SistemaFalso(cadenas=("MURO_INPUT",), saltos=(("INPUT", "MURO_INPUT"),))
    IptablesBackend(sistema, chain_prefix="MURO").apply_ruleset(Chain.INPUT, [])
    assert escrituras(sistema)[0] == ["iptables", "-F", "MURO_INPUT"]


# --------------------------------------------------------------------------- #
# read_ruleset
# --------------------------------------------------------------------------- #


def test_read_ruleset_lee_con_s_y_no_con_el_formato_tabular() -> None:
    """`iptables -S` imprime igual en todas las versiones probadas.

    El tabular no: la 1.8.10 saca la columna `prot` como numero donde la 1.8.11
    saca el nombre (hallazgo de B0). Leer el estado por el camino que no cambia
    es gratis y quita una clase entera de bugs por version.
    """
    sistema = montado(salidas={"-S": (FIXTURES / "cargado" / "save.txt").read_text()})
    IptablesBackend(sistema).read_ruleset(Chain.INPUT)
    assert ["iptables", "-S", "FWDASH_INPUT"] in sistema.vistos
    assert not any(a[1] == "-L" and "-v" in a for a in sistema.vistos)


def test_read_ruleset_devuelve_solo_su_cadena_y_conserva_lo_ajeno() -> None:
    """Sobre la salida REAL capturada en A2, con reglas de otras cadenas dentro.

    Lo no representable no se descarta: que un `multiport` aparezca en una cadena
    gestionada ES drift, y descartarlo en silencio lo escondería.
    """
    sistema = montado(salidas={"-S": (FIXTURES / "cargado" / "save.txt").read_text()})
    reglas = IptablesBackend(sistema).read_ruleset(Chain.INPUT)

    assert reglas and all(r.chain == "FWDASH_INPUT" for r in reglas)
    assert sum(1 for r in reglas if r.is_guardian) == 3
    assert any("multiport" in r.unsupported for r in reglas)
    assert any(r.spec is not None for r in reglas)


def test_leer_una_cadena_que_no_existe_lo_dice_con_claridad() -> None:
    """iptables no puede: su mensaje no distingue cadena de match. Este si.

    Por eso se PREGUNTA con un sondeo en vez de deducirlo del error de otro
    comando (la ambiguedad medida en A2).
    """
    with pytest.raises(FirewallCommandError) as error:
        IptablesBackend(SistemaFalso()).read_ruleset(Chain.INPUT)
    assert "FWDASH_INPUT" in error.value.message
    assert error.value.details == {"chain": "FWDASH_INPUT"}


# --------------------------------------------------------------------------- #
# read_counters
# --------------------------------------------------------------------------- #

#: Misma cadena, dos veces: como la imprime `-x` y como la abrevia sin `-x`.
CONTADORES_EXACTOS = """Chain FWDASH_INPUT (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0            /* fwdash:guardian:loopback */
  500123 42000456 DROP       tcp  --  *      *       10.0.0.5             0.0.0.0/0            tcp dpt:3306 /* fwdash:3f2504e0 */
"""

CONTADORES_ABREVIADOS = """Chain FWDASH_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0            /* fwdash:guardian:loopback */
 500K   42M DROP       tcp  --  *      *       10.0.0.5             0.0.0.0/0            tcp dpt:3306 /* fwdash:3f2504e0 */
"""


def test_los_contadores_se_piden_siempre_con_x() -> None:
    sistema = montado(salidas={"-L": CONTADORES_EXACTOS})
    IptablesBackend(sistema).read_counters(Chain.INPUT)
    assert ["iptables", "-L", "FWDASH_INPUT", "-v", "-n", "-x"] in sistema.vistos


def test_sin_x_los_numeros_se_pierden() -> None:
    """La contraprueba del test anterior: por que `-x` no es opcional.

    Sin el, iptables abrevia a `500K` y el contador deja de ser un contador. Es
    el fallo perfecto (A2): invisible durante los primeros mil paquetes, y
    despues silenciosamente mal en produccion.
    """
    con_x = IptablesBackend(montado(salidas={"-L": CONTADORES_EXACTOS}))
    sin_x = IptablesBackend(montado(salidas={"-L": CONTADORES_ABREVIADOS}))

    exacto = con_x.read_counters(Chain.INPUT)["3f2504e0"]
    abreviado = sin_x.read_counters(Chain.INPUT)["3f2504e0"]

    assert exacto.packets == 500123
    assert abreviado.packets == 500000, "el parser lee el sufijo, pero ya no es el numero"
    assert exacto.packets - abreviado.packets == 123


def test_los_guardianes_no_ensucian_los_contadores() -> None:
    """No salen de la tabla `rules`: no hay fila a la que devolverles el contador."""
    contadores = IptablesBackend(montado(salidas={"-L": CONTADORES_EXACTOS})).read_counters(
        Chain.INPUT
    )
    assert list(contadores) == ["3f2504e0"]


def test_los_contadores_vuelven_indexados_por_el_uuid_corto() -> None:
    """Es la clave con la que un contador vuelve a la fila que lo origino."""
    sistema = montado(salidas={"-L": CONTADORES_EXACTOS})
    contadores = IptablesBackend(sistema).read_counters(Chain.INPUT)
    assert contadores[UUID_A[:8]].bytes == 42000456


def test_contar_sobre_una_cadena_que_no_existe_falla() -> None:
    with pytest.raises(FirewallCommandError):
        IptablesBackend(SistemaFalso()).read_counters(Chain.INPUT)


# --------------------------------------------------------------------------- #
# teardown
# --------------------------------------------------------------------------- #


def test_teardown_deja_el_sistema_como_estaba() -> None:
    """El efecto, no la ausencia de error: ni cadenas ni saltos."""
    sistema = montado()
    IptablesBackend(sistema).apply_ruleset(Chain.INPUT, [regla()])
    assert sistema.cadenas and sistema.saltos, "contraprueba: antes SI habia algo montado"

    IptablesBackend(sistema).teardown()
    assert sistema.cadenas == set()
    assert sistema.saltos == []


def test_teardown_borra_el_salto_antes_de_la_cadena() -> None:
    """iptables se niega a borrar una cadena con referencias.

    Si el orden se invirtiera, el `-X` fallaria y -- al ir con `check=False` --
    fallaria EN SILENCIO, dejando cadenas huerfanas para siempre.
    """
    sistema = montado()
    IptablesBackend(sistema).teardown()

    # Los `-D` son varios: se repiten hasta que uno falla, que es como se sabe que
    # ya no queda ninguno. Lo que importa es que TODOS van antes del vaciado.
    orden = [a[1] for a in sistema.vistos if "FWDASH_INPUT" in a]
    assert orden[-2:] == ["-F", "-X"]
    assert set(orden[:-2]) == {"-D"}


def test_teardown_quita_tambien_los_saltos_duplicados() -> None:
    """`-D` borra solo la primera coincidencia.

    Un duplicado superviviente dejaria la cadena con referencias y el `-X` de
    despues fallaria sin decir nada.
    """
    sistema = montado()
    sistema.saltos.append(("INPUT", "FWDASH_INPUT"))
    sistema.saltos.append(("INPUT", "FWDASH_INPUT"))

    IptablesBackend(sistema).teardown()
    assert sistema.saltos == []
    assert sistema.cadenas == set()


def test_teardown_no_se_cuelga_si_el_salto_no_desaparece() -> None:
    """El tope del bucle. `-D` que siempre devuelve 0 no puede ser un cuelgue."""
    sistema = montado()
    sistema.saltos.extend([("INPUT", "FWDASH_INPUT")] * (MAX_SALTOS_DUPLICADOS + 5))

    IptablesBackend(sistema).teardown()
    borrados = [a for a in sistema.vistos if a[1] == "-D" and a[2] == "INPUT"]
    assert len(borrados) == MAX_SALTOS_DUPLICADOS


def test_teardown_sobre_un_sistema_limpio_no_falla() -> None:
    """Es lo que se llama cuando algo ha ido mal: tiene que poder llamarse dos veces."""
    sistema = SistemaFalso()
    IptablesBackend(sistema).teardown()
    IptablesBackend(sistema).teardown()
    assert sistema.cadenas == set()


# --------------------------------------------------------------------------- #
# Lo que nunca puede aparecer en un argv
# --------------------------------------------------------------------------- #


def test_ningun_argv_lleva_ruta_ni_sudo() -> None:
    """El renderer emite el nombre logico; resolver la ruta y poner `sudo` es del
    runner, y un `"sudo"` en el argv es `SecurityError` (B2). Este backend no
    puede ser quien lo introduzca."""
    sistema = montado(salidas={"-S": "", "-L": CONTADORES_EXACTOS})
    backend = IptablesBackend(sistema)
    backend.ensure_scaffold()
    backend.apply_ruleset(Chain.INPUT, [regla(uuid=UUID_A)])
    backend.read_ruleset(Chain.INPUT)
    backend.read_counters(Chain.INPUT)
    backend.teardown()

    assert sistema.vistos
    for argv in sistema.vistos:
        assert argv[0] == "iptables"
        assert "sudo" not in argv
        assert "/" not in argv[0]


def test_el_timeout_configurado_llega_a_todos_los_comandos() -> None:
    """El runner lo recibe por llamada, no en su constructor (B2).

    Un comando que se escape del sitio unico que lo inyecta correria con el valor
    por defecto en vez de con el del `.env`, y solo se notaria el dia que iptables
    se queda esperando el lock de xtables.
    """
    sistema = montado(salidas={"-S": "", "-L": CONTADORES_EXACTOS})
    backend = IptablesBackend(sistema, timeout=2.5)
    backend.ensure_scaffold()
    backend.apply_ruleset(Chain.INPUT, [regla(uuid=UUID_A)])
    backend.read_ruleset(Chain.INPUT)
    backend.read_counters(Chain.INPUT)
    backend.teardown()

    assert sistema.timeouts, "contraprueba: si no se ejecuto nada, no se prueba nada"
    assert set(sistema.timeouts) == {2.5}


def test_todo_argv_es_una_lista_de_cadenas() -> None:
    """Nada de `None` ni de enteros: el runner los rechaza, y con razon."""
    sistema = montado()
    IptablesBackend(sistema).apply_ruleset(Chain.INPUT, [regla(uuid=UUID_A)])
    for argv in sistema.vistos:
        assert all(isinstance(x, str) for x in argv), argv
