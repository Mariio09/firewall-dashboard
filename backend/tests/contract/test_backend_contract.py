"""B5 — el contrato de `FirewallBackend`, ejecutado contra los dos backends.

Esta suite es el antidoto contra el riesgo del que avisa `docs/ARCHITECTURE.md` §8:
que el doble de prueba MIENTA. Todo el bloque A se construyo contra
`FakeFirewallBackend`, asi que cada afirmacion de estos tests es una que el
bloque C da por buena. Si aqui el fake y iptables real no responden igual, el
"cambiar una variable de entorno" del ADR-0004 es falso, y vale mucho mas
descubrirlo ahora.

COMO ESTA ESCRITA, Y POR QUE ASI

- **Solo se usa el Protocol.** Ni un `iptables -S` a mano, ni un vistazo al
  diccionario interno del fake: si un test necesitara mirar por debajo, estaria
  comprobando una implementacion y no un contrato. Lo que hay que mirar por
  debajo va a `tests/e2e_vm/`, que es otra cosa y esta marcada como tal.
- **Se comprueba el EFECTO.** Ninguna aserción se conforma con "no lanzo
  excepcion": se lee el estado despues y se compara. Van cinco trampas en este
  proyecto de la familia "comprobar la cadena en vez del hecho", cuatro de ellas
  dentro de arneses escritos para evitarla → nota `Estrategia de tests`.
- **Cada invariante trae su contraprueba.** Un test que dice "esto no aparece"
  pasa igual si no aparece nunca nada.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import FirewallCommandError, InvalidRuleError
from app.firewall.base import FirewallBackend
from app.firewall.spec import Action, Chain, NativeRule, RuleSpec
from tests.contract.casos import GUARDIANES_POR_CADENA, specs_de_prueba

#: El marcador declarado en `pyproject.toml`: `pytest -m contract` corre esta
#: suite y solo esta. Un marcador declarado y sin usar es decoracion.
pytestmark = pytest.mark.contract

CADENA = Chain.INPUT


def de_usuario(reglas: list[NativeRule]) -> list[NativeRule]:
    return [r for r in reglas if not r.is_guardian]


def guardianes(reglas: list[NativeRule]) -> list[NativeRule]:
    return [r for r in reglas if r.is_guardian]


def estado(firewall: FirewallBackend, chain: Chain = CADENA) -> list[str]:
    """La cadena tal y como se lee, en texto: lo que hay que comparar antes y despues."""
    return [r.raw for r in firewall.read_ruleset(chain)]


# --------------------------------------------------------------------------- #
# Montaje y desmontaje
# --------------------------------------------------------------------------- #


def test_sin_scaffold_ninguna_operacion_funciona(firewall: FirewallBackend) -> None:
    """Y falla con el MISMO tipo de error en los dos backends.

    Importa porque `api/routers/firewall.py` traduce ese tipo a un 502: si el fake
    lanzara otra cosa, los tests de integracion del bloque A estarian validando un
    codigo HTTP que la VM no va a devolver.
    """
    for operacion in (
        lambda: firewall.read_ruleset(CADENA),
        lambda: firewall.read_counters(CADENA),
        lambda: firewall.apply_ruleset(CADENA, []),
    ):
        with pytest.raises(FirewallCommandError):
            operacion()


def test_ensure_scaffold_crea_la_cadena_VACIA(firewall: FirewallBackend) -> None:
    """Crear una cadena no es poblarla, y la diferencia la encontro B5.

    `ensure_scaffold` hace la cadena y el salto, punto. Los guardianes los emite
    el renderer en cabecera de cada ruleset, o sea que entran con el primer
    `apply_ruleset`. El fake enseñaba tres reglas donde iptables tenia una cadena
    vacia, y la mentira vivia exactamente en la ventana entre el arranque del
    servicio y la primera aplicacion: `GET /firewall/status` habria dicho cosas
    distintas en el Mac y en la VM.
    """
    firewall.ensure_scaffold()

    for chain in GUARDIANES_POR_CADENA:
        assert firewall.read_ruleset(chain) == []


def test_los_guardianes_entran_con_el_primer_apply(firewall: FirewallBackend) -> None:
    """La otra mitad del test anterior: la cadena vacia no se queda vacia.

    Sin esta, aquel pasaria igual si `read_ruleset` devolviera siempre una lista
    vacia, que es la forma mas barata de tener un test verde que no prueba nada.
    """
    firewall.ensure_scaffold()

    for chain, cuantos in GUARDIANES_POR_CADENA.items():
        firewall.apply_ruleset(chain, [])
        reglas = firewall.read_ruleset(chain)
        assert len(guardianes(reglas)) == cuantos
        assert de_usuario(reglas) == []


def test_ensure_scaffold_es_idempotente_y_no_borra_lo_aplicado(
    firewall: FirewallBackend,
) -> None:
    """`lifespan` lo llama en CADA arranque del servicio.

    Dos cosas que no puede hacer, y las dos se comprueban por efecto: duplicar el
    montaje, y llevarse por delante la politica que ya estaba aplicada. La segunda
    es la peligrosa: un `systemctl restart` que vaciara las cadenas dejaria la
    maquina sin la politica de la base de datos hasta el siguiente apply manual.
    """
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs_de_prueba(CADENA))
    antes = estado(firewall)

    firewall.ensure_scaffold()

    assert estado(firewall) == antes


def test_teardown_deja_el_sistema_como_estaba_y_se_puede_repetir(
    firewall: FirewallBackend,
) -> None:
    """`teardown` es lo que se llama cuando algo ha ido mal: no puede fallar.

    Tiene que funcionar sobre un montaje completo, sobre uno a medias y sobre uno
    que no existe. Que no lance no basta como prueba: se comprueba el efecto, que
    es que la cadena vuelva a no existir.
    """
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs_de_prueba(CADENA))

    firewall.teardown()
    with pytest.raises(FirewallCommandError):
        firewall.read_ruleset(CADENA)

    firewall.teardown()  # segunda vez, sobre un sistema ya limpio
    with pytest.raises(FirewallCommandError):
        firewall.read_ruleset(CADENA)


# --------------------------------------------------------------------------- #
# El viaje de ida y vuelta: es el test que cierra el ADR-0006
# --------------------------------------------------------------------------- #


def test_lo_que_se_aplica_vuelve_igual_por_estructura(firewall: FirewallBackend) -> None:
    """renderer -> firewall -> parser devuelve la MISMA `RuleSpec`.

    El quinto de los tests canonicos del proyecto, y el unico que no se podia
    escribir hasta tener la VM. iptables REESCRIBE lo que se le manda: añade
    `-m tcp`, reordena flags, normaliza mascaras. Comparar texto daria divergencia
    siempre; por eso el drift compara estructura (ADR-0006), y por eso esto es lo
    que hay que demostrar.

    Con el fake pasa por construccion —renderiza y parsea con el codigo de
    verdad—. Con iptables real, pasa o no pasa.
    """
    specs = specs_de_prueba(CADENA)
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs)

    leidas = de_usuario(firewall.read_ruleset(CADENA))

    assert [r.spec for r in leidas] == specs
    assert [r.unsupported for r in leidas] == [()] * len(specs)


def test_el_comentario_del_usuario_sobrevive_al_viaje(firewall: FirewallBackend) -> None:
    """La etiqueta lleva tres partes (`fwdash:<uuid8>:<texto>`) y las tres vuelven.

    Contraprueba del test anterior por otro lado: comparar specs no mira el
    comentario, porque `RuleSpec.comment` si entra en la igualdad pero el uuid no.
    Aqui se comprueba la identidad, que es lo que ata un contador a su fila.
    """
    specs = specs_de_prueba(CADENA)
    con_comentario = next(s for s in specs if s.comment)

    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs)

    leidas = de_usuario(firewall.read_ruleset(CADENA))
    encontrada = next(r for r in leidas if r.rule_uuid == con_comentario.short_uuid)
    assert encontrada.comment == f"fwdash:{con_comentario.short_uuid}:{con_comentario.comment}"


# --------------------------------------------------------------------------- #
# Reconstruccion: la unica operacion de escritura
# --------------------------------------------------------------------------- #


def test_aplicar_reconstruye_la_cadena_entera_y_no_acumula(firewall: FirewallBackend) -> None:
    """No hay `add_rule`: aplicar es dejar la cadena EXACTAMENTE con esas specs."""
    specs = specs_de_prueba(CADENA)
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs)
    assert len(de_usuario(firewall.read_ruleset(CADENA))) == len(specs)

    firewall.apply_ruleset(CADENA, specs[:1])

    quedan = de_usuario(firewall.read_ruleset(CADENA))
    assert [r.spec for r in quedan] == specs[:1]
    assert len(guardianes(firewall.read_ruleset(CADENA))) == GUARDIANES_POR_CADENA[CADENA]


def test_aplicar_dos_veces_lo_mismo_deja_exactamente_lo_mismo(firewall: FirewallBackend) -> None:
    """Idempotencia, que es lo que hace segura la reparacion tras un fallo a mitad."""
    specs = specs_de_prueba(CADENA)
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs)
    primera = estado(firewall)

    firewall.apply_ruleset(CADENA, specs)

    assert estado(firewall) == primera


def test_el_orden_de_las_specs_es_el_orden_de_la_cadena(firewall: FirewallBackend) -> None:
    """En iptables el orden ES la semantica: gana la primera que hace match."""
    specs = specs_de_prueba(CADENA)
    firewall.ensure_scaffold()

    firewall.apply_ruleset(CADENA, list(reversed(specs)))

    leidas = de_usuario(firewall.read_ruleset(CADENA))
    assert [r.spec for r in leidas] == list(reversed(specs))


def test_los_guardianes_van_siempre_delante(firewall: FirewallBackend) -> None:
    """Y no hay ninguna ruta para quitarlos: `apply_ruleset` los vuelve a poner.

    Es la propiedad que sostiene todo el bloque B4: el `-F` va seguido de los
    guardianes, asi que un corte a mitad pierde reglas de usuario, nunca el acceso.
    """
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs_de_prueba(CADENA))

    reglas = firewall.read_ruleset(CADENA)
    cuantos = GUARDIANES_POR_CADENA[CADENA]

    assert all(r.is_guardian for r in reglas[:cuantos])
    assert not any(r.is_guardian for r in reglas[cuantos:])
    assert all(r.target == Action.ACCEPT.value for r in reglas[:cuantos])


def test_una_spec_de_otra_cadena_no_deja_la_cadena_a_medias(firewall: FirewallBackend) -> None:
    """Se renderiza ENTERO antes de ejecutar nada, asi que el sistema no se toca.

    Sin esta garantia, un error de programacion vaciaria la cadena y la dejaria
    sin guardianes: el modo de auto-bloqueo mas tonto posible.
    """
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs_de_prueba(CADENA))
    antes = estado(firewall)

    ajena = RuleSpec(chain=Chain.OUTPUT, action=Action.DROP, dst_ip="203.0.113.9")
    with pytest.raises(InvalidRuleError):
        firewall.apply_ruleset(CADENA, [*specs_de_prueba(CADENA), ajena])

    assert estado(firewall) == antes


# --------------------------------------------------------------------------- #
# Preview
# --------------------------------------------------------------------------- #


def test_el_dry_run_enseña_lo_que_se_ejecutaria_y_no_ejecuta_nada(
    firewall: FirewallBackend,
) -> None:
    """`GET /firewall/preview` promete dos cosas, y las dos se comprueban aqui.

    Que no ejecuta: comparando el estado antes y despues. Y que lo que enseña es
    lo que se ejecutara: comparando su argv con el del apply de verdad. Un preview
    que enseñe otra cosa es peor que no tenerlo.
    """
    specs = specs_de_prueba(CADENA)
    firewall.ensure_scaffold()
    antes = estado(firewall)

    previsto = firewall.apply_ruleset(CADENA, specs, dry_run=True)

    assert previsto.dry_run is True
    assert previsto.commands
    assert estado(firewall) == antes

    real = firewall.apply_ruleset(CADENA, specs)
    assert real.dry_run is False
    assert real.commands == previsto.commands
    assert estado(firewall) != antes  # contraprueba: el apply de verdad SI toca


# --------------------------------------------------------------------------- #
# Contadores
# --------------------------------------------------------------------------- #


def test_los_contadores_se_indexan_por_uuid_y_excluyen_a_los_guardianes(
    firewall: FirewallBackend,
) -> None:
    """La clave es el uuid corto: es lo que devuelve el contador a su fila.

    Los guardianes no salen de la tabla `rules`, asi que no hay fila a la que
    devolverles nada; y la spec sin uuid (la de icmp) tampoco aparece, que es la
    contraprueba de que la clave viene de la etiqueta y no de la posicion.
    """
    specs = specs_de_prueba(CADENA)
    con_uuid = {s.short_uuid for s in specs if s.short_uuid}

    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, specs)

    contadores = firewall.read_counters(CADENA)

    assert set(contadores) == con_uuid
    assert all(c.packets >= 0 and c.bytes >= 0 for c in contadores.values())
