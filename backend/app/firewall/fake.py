"""Backend en memoria. Es lo que permite construir el MVP entero sin VM.

Bloque A3. Implementa el mismo `FirewallBackend` que `IptablesBackend`, guardando
las reglas en un diccionario. Se usa en dos sitios:

  - En los tests (unitarios, de integracion y de contrato).
  - En desarrollo real, con `FIREWALL_BACKEND=fake` en el `.env` del Mac. El
    dashboard funciona de punta a punta contra este backend.

EL RIESGO DE ESTE ARCHIVO (docs/ARCHITECTURE.md §8): un doble de prueba puede
mentir. Si se implementa "como me imagino que se comporta iptables" en lugar de
como se comporta de verdad, el bloque C deja de ser un cambio de variable y se
convierte en una reescritura.

Dos medidas obligatorias contra eso:
  1. El parser y el renderer se diseñan contra salidas REALES capturadas en
     `tests/fixtures/iptables_output/` (paso A2).
  2. `tests/contract/` ejecuta la misma suite contra este backend y contra el
     real. En el Mac corre solo con el fake; en la VM, con los dos. Cualquier
     divergencia salta en el bloque B, no cuando ya hay un frontend encima.

Por eso este fake debe imitar tambien los FALLOS de iptables, no solo sus exitos:
cadena inexistente, regla duplicada, orden de aplicacion.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.firewall.spec import ApplyResult, Chain, Counters, NativeRule, RuleSpec


class FakeFirewallBackend:
    """Backend en memoria que cumple el Protocol `FirewallBackend`.

    TODO(A3): implementar. Mantener el estado en `self._chains: dict[Chain, list[RuleSpec]]`
    y `self._scaffolded: bool`, y hacer que `apply_ruleset` reemplace la lista
    entera (no que haga append) para reproducir la semantica de reconstruccion.
    """

    def __init__(self) -> None:
        self._chains: dict[Chain, list[RuleSpec]] = {}
        self._scaffolded = False

    def ensure_scaffold(self) -> None:
        raise NotImplementedError("TODO(A3)")

    def apply_ruleset(
        self,
        chain: Chain,
        specs: Sequence[RuleSpec],
        *,
        dry_run: bool = False,
    ) -> ApplyResult:
        raise NotImplementedError("TODO(A3)")

    def read_ruleset(self, chain: Chain) -> list[NativeRule]:
        raise NotImplementedError("TODO(A3)")

    def read_counters(self, chain: Chain) -> dict[str, Counters]:
        raise NotImplementedError("TODO(A3)")

    def teardown(self) -> None:
        raise NotImplementedError("TODO(A3)")
