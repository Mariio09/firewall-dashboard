"""Validacion y normalizacion de TODA entrada que acaba en un comando iptables.

Bloque A3. Ningun otro modulo del proyecto tiene permiso para interpretar una IP,
un puerto o un nombre de interfaz. Si aparece `ipaddress.ip_network(...)` fuera de
este archivo, es un bug de arquitectura.

Cada funcion normaliza ademas de validar: devuelve la forma canonica que se
guardara en la base de datos. Asi `1.2.3.4` y `1.2.3.4/32` acaban siendo la misma
fila y las comparaciones de drift funcionan.

TODO(A3): implementar. Los tests van primero (tests/unit/firewall/), y los cuatro
primeros del proyecto estan listados en docs/ARCHITECTURE.md §5.4.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.firewall.spec import Chain, RuleSpec

# Longitud maxima real del --log-prefix de iptables (29 caracteres utiles).
MAX_LOG_PREFIX_LEN = 29

# Longitud maxima de un nombre de interfaz en Linux (IFNAMSIZ - 1).
MAX_INTERFACE_LEN = 15

MIN_PORT = 1
MAX_PORT = 65535


def validate_ip_or_cidr(value: str, *, ip_version: int = 4) -> str:
    """Valida una IP o red y la devuelve normalizada a notacion CIDR.

    '1.2.3.4' -> '1.2.3.4/32'.  Lanza `InvalidRuleError` si no es valida o si no
    corresponde a la familia pedida.
    """
    raise NotImplementedError("TODO(A3)")


def validate_port_spec(value: str) -> str:
    """Valida un puerto o rango de puertos.

    Acepta '80' y '8000:8010'. Rechaza 0, >65535, rangos invertidos y cualquier
    cosa que no sea digitos y como mucho un ':'.
    """
    raise NotImplementedError("TODO(A3)")


def validate_interface(value: str) -> str:
    """Valida un nombre de interfaz de red (`eth0`, `enp0s1`, `lo`)."""
    raise NotImplementedError("TODO(A3)")


def validate_log_prefix(value: str) -> str:
    """Valida un --log-prefix: longitud acotada, sin comillas ni saltos de linea."""
    raise NotImplementedError("TODO(A3)")


def validate_managed_chain_name(prefix: str, chain: Chain) -> str:
    """Construye y valida el nombre de la cadena gestionada. 'FWDASH' + INPUT -> 'FWDASH_INPUT'."""
    raise NotImplementedError("TODO(A3)")


def validate_spec(spec: RuleSpec) -> None:
    """Valida una `RuleSpec` completa, incluidas las reglas cruzadas.

    Ejemplos de reglas cruzadas que un validador por campo no puede detectar:
      - especificar un puerto con `protocol=icmp` o `protocol=all`
      - usar `out_interface` en la cadena INPUT (iptables lo rechaza)
      - usar `in_interface` en la cadena OUTPUT
      - `log_enabled=True` sin `log_prefix`
    """
    raise NotImplementedError("TODO(A3)")
