"""Tests de `app/firewall/fake.py`.

Lo que se comprueba aqui no es "el fake guarda cosas en un diccionario", sino que
se comporta como el contrato dice que se comporta un firewall: reconstruccion
completa en vez de append, fallo cuando la cadena no existe, y guardianes en
cabecera de cada ruleset aplicado. Si el fake miente, el bloque C deja de ser un
cambio de variable de entorno y se convierte en una reescritura.

Y mintio una vez: hasta B5, `read_ruleset` devolvia los guardianes en cuanto la
cadena existia, aunque no se hubiera aplicado nada. iptables devuelve una cadena
vacia. Lo cazo `tests/contract/` contra la VM.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import FirewallCommandError, InvalidRuleError
from app.firewall.base import FirewallBackend
from app.firewall.fake import FakeFirewallBackend
from app.firewall.spec import Action, Chain, Counters, Protocol, RuleSpec

UUID_A = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
UUID_B = "9c5b94b1-35ad-49bb-b118-8e8fc24abf80"


def backend_listo() -> FakeFirewallBackend:
    fake = FakeFirewallBackend()
    fake.ensure_scaffold()
    return fake


def regla(ip: str, *, uuid: str | None = None) -> RuleSpec:
    return RuleSpec(
        chain=Chain.INPUT,
        action=Action.DROP,
        protocol=Protocol.TCP,
        src_ip=ip,
        dst_port="22",
        rule_uuid=uuid,
    )


def test_el_fake_cumple_el_protocol() -> None:
    assert isinstance(FakeFirewallBackend(), FirewallBackend)


def test_sin_scaffold_falla_como_falla_iptables() -> None:
    """Mismo mensaje que dio la VM en A2, literal."""
    with pytest.raises(FirewallCommandError) as error:
        FakeFirewallBackend().apply_ruleset(Chain.INPUT, [])
    assert error.value.message == "iptables: No chain/target/match by that name."


def test_ensure_scaffold_es_idempotente() -> None:
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4")])
    fake.ensure_scaffold()
    assert len([r for r in fake.read_ruleset(Chain.INPUT) if r.spec is not None]) == 1


def test_una_cadena_creada_y_nunca_aplicada_esta_vacia() -> None:
    """Como iptables: `-N` crea la cadena y no mete nada dentro (B5).

    La contraprueba va pegada, porque "esta vacia" pasaria igual si `read_ruleset`
    no devolviera nunca nada.
    """
    fake = backend_listo()
    assert fake.read_ruleset(Chain.INPUT) == []

    fake.apply_ruleset(Chain.INPUT, [])
    assert [r.comment for r in fake.read_ruleset(Chain.INPUT)] != []


def test_aplicar_reconstruye_la_cadena_entera() -> None:
    """No hay add ni delete: el estado final solo depende de lo que se pasa."""
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4"), regla("5.6.7.8")])
    fake.apply_ruleset(Chain.INPUT, [regla("9.9.9.9")])

    aplicadas = [r.spec for r in fake.read_ruleset(Chain.INPUT) if r.spec is not None]
    assert [s.src_ip for s in aplicadas if s is not None] == ["9.9.9.9/32"]


def test_lo_que_entra_es_lo_que_sale() -> None:
    """El round-trip completo: renderer -> texto -> parser. Es el mismo camino que
    recorrera el backend real, y por eso el fake no puede inventarse un formato."""
    fake = backend_listo()
    original = RuleSpec(
        chain=Chain.INPUT,
        action=Action.ACCEPT,
        protocol=Protocol.TCP,
        src_ip="192.168.64.0/24",
        dst_port="8000",
        comment="api desde la red host-only",
        rule_uuid=UUID_A,
    )
    fake.apply_ruleset(Chain.INPUT, [original])

    leidas = [r for r in fake.read_ruleset(Chain.INPUT) if r.spec is not None]
    assert len(leidas) == 1
    assert leidas[0].spec == original
    assert leidas[0].rule_uuid == "3f2504e0"


def test_una_regla_con_log_sobrevive_al_round_trip() -> None:
    fake = backend_listo()
    original = RuleSpec(
        chain=Chain.INPUT,
        action=Action.DROP,
        protocol=Protocol.TCP,
        dst_port="23",
        log_enabled=True,
        log_prefix="FWDASH DROP: ",
        rule_uuid=UUID_A,
    )
    fake.apply_ruleset(Chain.INPUT, [original])
    leidas = [r for r in fake.read_ruleset(Chain.INPUT) if r.spec is not None]
    assert [r.spec for r in leidas] == [original]


def test_los_guardianes_estan_siempre_y_no_son_reglas_de_usuario() -> None:
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [])
    leidas = fake.read_ruleset(Chain.INPUT)
    assert len(leidas) == 3
    assert all(r.is_guardian for r in leidas)
    assert all(r.spec is None for r in leidas)


def test_el_dry_run_no_toca_el_estado() -> None:
    fake = backend_listo()
    resultado = fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4")], dry_run=True)

    assert resultado.dry_run is True
    assert resultado.applied == 1
    assert resultado.commands[0] == ("iptables", "-F", "FWDASH_INPUT")
    assert [r for r in fake.read_ruleset(Chain.INPUT) if r.spec is not None] == []


def test_una_spec_de_otra_cadena_no_deja_la_cadena_a_medias() -> None:
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4")])

    with pytest.raises(InvalidRuleError):
        fake.apply_ruleset(
            Chain.INPUT, [regla("5.6.7.8"), RuleSpec(chain=Chain.OUTPUT, action=Action.DROP)]
        )

    intactas = [r.spec for r in fake.read_ruleset(Chain.INPUT) if r.spec is not None]
    assert [s.src_ip for s in intactas if s is not None] == ["1.2.3.4/32"]


def test_las_cadenas_son_independientes() -> None:
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4")])
    fake.apply_ruleset(Chain.OUTPUT, [])
    assert len([r for r in fake.read_ruleset(Chain.INPUT) if r.spec is not None]) == 1


def test_contadores_a_cero_y_trafico_simulado() -> None:
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4", uuid=UUID_A), regla("5.6.7.8", uuid=UUID_B)])

    assert fake.read_counters(Chain.INPUT) == {"3f2504e0": Counters(), "9c5b94b1": Counters()}

    fake.simulate_traffic(UUID_A, packets=10, bytes=800)
    fake.simulate_traffic(UUID_A, packets=5, bytes=400)
    assert fake.read_counters(Chain.INPUT)["3f2504e0"] == Counters(packets=15, bytes=1200)


def test_las_reglas_sin_uuid_no_aparecen_en_los_contadores() -> None:
    """Una spec de `preview` no tiene fila a la que atribuirle trafico."""
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4")])
    assert fake.read_counters(Chain.INPUT) == {}


def test_teardown_deja_el_backend_como_estaba() -> None:
    fake = backend_listo()
    fake.apply_ruleset(Chain.INPUT, [regla("1.2.3.4")])
    fake.teardown()
    with pytest.raises(FirewallCommandError):
        fake.read_ruleset(Chain.INPUT)
