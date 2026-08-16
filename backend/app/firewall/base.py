"""El contrato que separa la aplicacion del sistema operativo.

Bloque A3. Esta es LA costura del proyecto: `FirewallBackend` tiene dos
implementaciones intercambiables (`fake.FakeFirewallBackend` e
`iptables.IptablesBackend`), y `api/deps.get_firewall_backend()` elige una u otra
segun `settings.firewall_backend`.

Consecuencia practica: el MVP completo se construye y se demuestra en el Mac, sin
VM y sin privilegios (bloque A). El bloque C se reduce a cambiar una variable de
entorno.

Nota de diseño: solo hay UNA operacion de escritura. No existe `add_rule()` ni
`delete_rule()`. "Aplicar" siempre significa reconstruir la cadena entera desde la
base de datos, lo que hace la operacion idempotente y elimina toda una clase de
estados inconsistentes (ADR-0002).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from app.firewall.spec import ApplyResult, Chain, Counters, NativeRule, RuleSpec


@runtime_checkable
class FirewallBackend(Protocol):
    """Operaciones que la aplicacion necesita del firewall subyacente."""

    def ensure_scaffold(self) -> None:
        """Crea las cadenas FWDASH_* y los saltos desde INPUT/OUTPUT/FORWARD.

        Idempotente: si ya existen, no hace nada. Es lo primero que se ejecuta al
        arrancar la aplicacion.
        """
        ...

    def apply_ruleset(
        self,
        chain: Chain,
        specs: Sequence[RuleSpec],
        *,
        dry_run: bool = False,
    ) -> ApplyResult:
        """Reconstruye la cadena gestionada para que contenga exactamente `specs`.

        Con `dry_run=True` devuelve los comandos que se ejecutarian sin ejecutar
        ninguno: es lo que alimenta el endpoint GET /firewall/preview.
        """
        ...

    def read_ruleset(self, chain: Chain) -> list[NativeRule]:
        """Lee el estado real de la cadena gestionada, para detectar drift."""
        ...

    def read_counters(self, chain: Chain) -> dict[str, Counters]:
        """Devuelve contadores de paquetes/bytes indexados por uuid de regla."""
        ...

    def teardown(self) -> None:
        """Elimina cadenas y saltos. Deja el sistema como estaba antes de la app."""
        ...
