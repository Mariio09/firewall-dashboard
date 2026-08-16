"""Backend real. Es el unico modulo que habla con el sistema, via `CommandRunner`.

Bloque B3. Todo lo demas de este paquete ya esta construido y testeado cuando se
llega aqui: este archivo solo pega `renderer` (que produce argv), `runner` (que los
ejecuta) y `parser` (que lee la respuesta).

No contiene logica de validacion: cuando una `RuleSpec` llega hasta aqui, ya es
valida por construccion.

Estrategia de aplicacion (ADR-0002): flush de la cadena gestionada + append de
todas las reglas en orden. La evolucion natural, si el rendimiento llegara a
importar, es construir el ruleset completo y aplicarlo de una vez con
`iptables-restore -n`, que ademas es atomico.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.firewall.runner import CommandRunner
from app.firewall.spec import ApplyResult, Chain, Counters, NativeRule, RuleSpec


class IptablesBackend:
    """Implementacion de `FirewallBackend` sobre iptables real.

    El `CommandRunner` se inyecta por constructor: esa es la costura que permite
    testear la construccion del argv y el parseo sin ejecutar iptables.

    TODO(B3): implementar.
    """

    def __init__(
        self,
        runner: CommandRunner,
        *,
        chain_prefix: str = "FWDASH",
        table: str = "filter",
        management_port: int = 8000,
        management_cidr: str = "192.168.64.0/24",
    ) -> None:
        self._runner = runner
        self._chain_prefix = chain_prefix
        self._table = table
        self._management_port = management_port
        self._management_cidr = management_cidr

    def ensure_scaffold(self) -> None:
        raise NotImplementedError("TODO(B3)")

    def apply_ruleset(
        self,
        chain: Chain,
        specs: Sequence[RuleSpec],
        *,
        dry_run: bool = False,
    ) -> ApplyResult:
        raise NotImplementedError("TODO(B3)")

    def read_ruleset(self, chain: Chain) -> list[NativeRule]:
        raise NotImplementedError("TODO(B3)")

    def read_counters(self, chain: Chain) -> dict[str, Counters]:
        raise NotImplementedError("TODO(B3)")

    def teardown(self) -> None:
        raise NotImplementedError("TODO(B3)")
