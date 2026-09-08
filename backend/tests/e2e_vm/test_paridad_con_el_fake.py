"""¿Miente el fake? Los dos backends, lado a lado, con las mismas specs.

Esta es la pregunta que sostiene el proyecto entero. Todo el bloque A se
construyo contra `FakeFirewallBackend` (ADR-0004), y el bloque C es "cambiar una
variable de entorno" SOLO si esa frase es verdad. La suite de contrato comprueba
que los dos cumplen las mismas reglas; esto comprueba algo mas fuerte: que ante
la misma entrada producen la MISMA lectura.

Se compara por estructura y no por texto, y no es una concesion: iptables
reescribe lo que se le manda (`-p tcp` -> `-p tcp -m tcp`), asi que comparar
`raw` daria rojo permanente sin que nada este mal. Comparar `RuleSpec` es
exactamente lo que hace la deteccion de drift (ADR-0006), asi que este test
compara lo mismo que el codigo de produccion compara.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.firewall.base import FirewallBackend
from app.firewall.fake import FakeFirewallBackend
from app.firewall.spec import Chain
from tests.contract.casos import PARAMETROS_DEL_BACKEND, specs_de_prueba

pytestmark = pytest.mark.requires_iptables

CADENAS = list(Chain)


def retrato(backend: FirewallBackend, chain: Chain) -> list[tuple[Any, ...]]:
    """Lo que un backend dice de una cadena, en forma comparable.

    `raw` se deja fuera a proposito (iptables reescribe); `spec`, `comment`,
    `target`, `rule_uuid`, `unsupported` y el orden, dentro: es todo lo que la
    aplicacion mira para decidir si hay drift y a quien pertenece un contador.
    """
    return [
        (r.spec, r.comment, r.target, r.rule_uuid, r.is_guardian, r.unsupported, r.is_log_half)
        for r in backend.read_ruleset(chain)
    ]


@pytest.fixture
def fake() -> FakeFirewallBackend:
    return FakeFirewallBackend(**PARAMETROS_DEL_BACKEND)


def test_los_dos_backends_leen_lo_mismo_en_las_tres_cadenas(
    firewall: FirewallBackend, fake: FakeFirewallBackend
) -> None:
    """Mismas specs dentro, misma lectura fuera. En las tres cadenas."""
    firewall.ensure_scaffold()
    fake.ensure_scaffold()

    for chain in CADENAS:
        specs = specs_de_prueba(chain)
        firewall.apply_ruleset(chain, specs)
        fake.apply_ruleset(chain, specs)

        assert retrato(firewall, chain) == retrato(fake, chain), (
            f"el fake y iptables no leen igual la cadena {chain.value}: "
            "si esto falla, el bloque C no es un cambio de variable de entorno"
        )


def test_la_comparacion_sabe_ver_una_diferencia(
    firewall: FirewallBackend, fake: FakeFirewallBackend
) -> None:
    """La contraprueba del test de arriba, y no es opcional.

    Un `retrato()` que se dejara fuera lo que importa daria igualdad siempre, y el
    test anterior pasaria sobre dos backends que no se parecen en nada. Aqui se le
    da a cada uno una entrada DISTINTA a proposito y se exige que la comparacion
    lo note.
    """
    firewall.ensure_scaffold()
    fake.ensure_scaffold()

    specs = specs_de_prueba(Chain.INPUT)
    firewall.apply_ruleset(Chain.INPUT, specs)
    fake.apply_ruleset(Chain.INPUT, specs[:-1])

    assert retrato(firewall, Chain.INPUT) != retrato(fake, Chain.INPUT)


def test_el_preview_de_los_dos_es_el_mismo_argv(
    firewall: FirewallBackend, fake: FakeFirewallBackend
) -> None:
    """`GET /firewall/preview` con el fake tiene que enseñar lo que hara la VM.

    Es lo que hace util desarrollar el frontend en el host: si el preview del fake
    no fuera el argv real, la pantalla mas util del dashboard estaria mintiendo.
    """
    firewall.ensure_scaffold()
    fake.ensure_scaffold()
    specs = specs_de_prueba(Chain.INPUT)

    del_real = firewall.apply_ruleset(Chain.INPUT, specs, dry_run=True)
    del_fake = fake.apply_ruleset(Chain.INPUT, specs, dry_run=True)

    assert del_real.commands == del_fake.commands


def test_los_contadores_se_indexan_igual_en_los_dos(
    firewall: FirewallBackend, fake: FakeFirewallBackend
) -> None:
    """Las claves, no los valores: los del fake son cero y los reales no tienen por que.

    Que las CLAVES coincidan es lo que garantiza que el dashboard ate cada
    contador a la misma fila en el host y en la VM.
    """
    firewall.ensure_scaffold()
    fake.ensure_scaffold()
    specs = specs_de_prueba(Chain.INPUT)
    firewall.apply_ruleset(Chain.INPUT, specs)
    fake.apply_ruleset(Chain.INPUT, specs)

    assert set(firewall.read_counters(Chain.INPUT)) == set(fake.read_counters(Chain.INPUT))
