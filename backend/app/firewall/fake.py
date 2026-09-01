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

Tres medidas contra eso, y la tercera es la de A3:

  1. El parser y el renderer se diseñaron contra salidas REALES capturadas en
     `tests/fixtures/iptables_output/` (paso A2).
  2. `tests/contract/` ejecuta la misma suite contra este backend y contra el
     real. En el Mac corre solo con el fake; en la VM, con los dos.
  3. **Este fake no reimplementa nada.** Renderiza con el `renderer` de verdad y
     lee de vuelta con el `parser` de verdad: lo unico que finge es el sistema
     operativo que habria en medio. Asi no puede inventarse un formato propio, y
     si el renderer o el parser tienen un bug, aparece aqui tambien.

Y por eso imita tambien los FALLOS: pedir una cadena que no existe devuelve el
mismo `FirewallCommandError` con el mismo mensaje que dio la VM en A2
(`tests/fixtures/iptables_output/error_chain_missing.txt`).
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence

from app.core.exceptions import FirewallCommandError
from app.firewall import validators
from app.firewall.parser import parse_save_format
from app.firewall.renderer import render_ruleset
from app.firewall.spec import ApplyResult, Chain, Counters, NativeRule, RuleSpec

__all__ = ["FakeFirewallBackend"]

#: Literal capturado de la VM en A2. iptables da el MISMO mensaje para una cadena
#: inexistente y para un match inexistente: no se pueden distinguir por el texto.
MENSAJE_CADENA_INEXISTENTE = "iptables: No chain/target/match by that name."


class FakeFirewallBackend:
    """Backend en memoria que cumple el Protocol `FirewallBackend`."""

    def __init__(
        self,
        *,
        chain_prefix: str = "FWDASH",
        management_port: int = 8000,
        management_cidr: str = "192.168.64.0/24",
    ) -> None:
        self._chain_prefix = chain_prefix
        self._management_port = management_port
        self._management_cidr = management_cidr
        self._chains: dict[Chain, list[RuleSpec]] = {}
        self._counters: dict[str, Counters] = {}
        self._scaffolded = False

    # ----------------------------------------------------------------------- #
    # Interno
    # ----------------------------------------------------------------------- #

    def _nombre_cadena(self, chain: Chain) -> str:
        return validators.validate_managed_chain_name(self._chain_prefix, chain)

    def _exigir_cadena(self, chain: Chain) -> str:
        """Falla como falla iptables cuando la cadena gestionada no existe."""
        nombre = self._nombre_cadena(chain)
        if not self._scaffolded or chain not in self._chains:
            raise FirewallCommandError(
                MENSAJE_CADENA_INEXISTENTE,
                details={"chain": nombre},
            )
        return nombre

    def _comandos(self, chain: Chain, specs: Sequence[RuleSpec]) -> list[list[str]]:
        return render_ruleset(
            chain,
            self._nombre_cadena(chain),
            specs,
            management_port=self._management_port,
            management_cidr=self._management_cidr,
        )

    # ----------------------------------------------------------------------- #
    # FirewallBackend
    # ----------------------------------------------------------------------- #

    def ensure_scaffold(self) -> None:
        """Crea las cadenas gestionadas. Idempotente: no borra lo que ya hubiera."""
        for chain in Chain:
            self._chains.setdefault(chain, [])
        self._scaffolded = True

    def apply_ruleset(
        self,
        chain: Chain,
        specs: Sequence[RuleSpec],
        *,
        dry_run: bool = False,
    ) -> ApplyResult:
        """Reemplaza la cadena entera, nunca añade.

        El orden importa: primero se renderiza y solo despues se toca el estado.
        Si una spec es de otra cadena, el renderer lo detecta y el fake se queda
        como estaba, igual que una cadena real no queda a medias cuando falla el
        primer comando.
        """
        self._exigir_cadena(chain)
        comandos = self._comandos(chain, specs)

        if not dry_run:
            self._chains[chain] = list(specs)

        return ApplyResult(
            chain=chain,
            applied=len(specs),
            commands=tuple(tuple(comando) for comando in comandos),
            dry_run=dry_run,
        )

    def read_ruleset(self, chain: Chain) -> list[NativeRule]:
        """Devuelve la cadena tal y como la leeria el backend real.

        Se renderiza el estado guardado y se vuelve a parsear con el parser de
        verdad, en vez de devolver las specs guardadas directamente. Es mas
        trabajo y es justo lo que hace util al fake: lo que sale de aqui ha
        pasado por el mismo camino que lo que saldra de la VM, guardianes
        incluidos.
        """
        nombre = self._exigir_cadena(chain)
        lineas = [
            shlex.join(comando[1:])
            for comando in self._comandos(chain, self._chains[chain])
            if comando[1] == "-A"
        ]
        return parse_save_format("\n".join(lineas), nombre)

    def read_counters(self, chain: Chain) -> dict[str, Counters]:
        """Contadores por uuid corto. Cero salvo que se hayan simulado."""
        self._exigir_cadena(chain)
        return {
            spec.short_uuid: self._counters.get(spec.short_uuid, Counters())
            for spec in self._chains[chain]
            if spec.short_uuid is not None
        }

    def teardown(self) -> None:
        """Deja el backend como recien construido."""
        self._chains.clear()
        self._counters.clear()
        self._scaffolded = False

    # ----------------------------------------------------------------------- #
    # Solo para tests y para la demo
    # ----------------------------------------------------------------------- #

    def simulate_traffic(self, rule_uuid: str, *, packets: int, bytes: int) -> None:  # noqa: A002
        """Suma trafico a una regla, para que el dashboard tenga algo que enseñar.

        Sin esto, `FIREWALL_BACKEND=fake` produce una UI en la que todos los
        contadores son cero para siempre, que es una demo pobre y ademas esconde
        los bugs de formateo de numeros grandes.
        """
        clave = validators.validate_rule_uuid(rule_uuid)[:8]
        actual = self._counters.get(clave, Counters())
        self._counters[clave] = Counters(
            packets=actual.packets + packets, bytes=actual.bytes + bytes
        )
