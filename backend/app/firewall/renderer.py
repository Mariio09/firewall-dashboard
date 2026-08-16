"""Traduce `RuleSpec` a argv de iptables. Funcion pura, sin efectos.

Bloque A3. No ejecuta nada: convierte datos en listas de strings. Por eso se puede
construir y testear entero en el Mac, y por eso es trivial de verificar.

Aqui viven tambien las REGLAS GUARDIAN (docs/ARCHITECTURE.md §0). No estan en la
base de datos, no se pueden desactivar por API y se emiten siempre en la cabecera
de cada cadena gestionada. Son lo que impide que una regla de usuario te deje sin
acceso a la VM ni a la propia API.

El caso mas traicionero es el de OUTPUT: sin un ACCEPT de ESTABLISHED,RELATED en
salida, una regla que filtre trafico saliente corta las RESPUESTAS de la API. La
peticion entra bien pero nunca vuelve, y desde el navegador parece un timeout
generico.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.firewall.spec import Chain, RuleSpec


def render_rule(chain_name: str, spec: RuleSpec) -> list[list[str]]:
    """Devuelve los argv de una spec.

    Devuelve una LISTA de comandos, no uno solo: con `log_enabled=True` (fase 2)
    una spec produce dos reglas, el LOG y la de accion, y el LOG debe ir primero
    o no registra nada.
    """
    raise NotImplementedError("TODO(A3)")


def render_guard_rules(
    chain: Chain, *, management_port: int, management_cidr: str
) -> list[list[str]]:
    """Reglas guardian de una cadena. Ver la tabla de docs/ARCHITECTURE.md §0.

    INPUT   : ESTABLISHED,RELATED + lo + puerto de gestion desde management_cidr
    OUTPUT  : ESTABLISHED,RELATED + lo + desde el puerto de gestion hacia management_cidr
    FORWARD : ESTABLISHED,RELATED
    """
    raise NotImplementedError("TODO(A3)")


def render_ruleset(
    chain: Chain,
    chain_name: str,
    specs: Sequence[RuleSpec],
    *,
    management_port: int,
    management_cidr: str,
) -> list[list[str]]:
    """Ruleset completo de una cadena: flush, guardianes y reglas de usuario en orden."""
    raise NotImplementedError("TODO(A3)")
