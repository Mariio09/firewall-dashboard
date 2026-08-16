"""Tipos frontera de la capa de firewall.

Bloque A3. `RuleSpec` es el tipo que cruza la frontera entre la logica de negocio
y el sistema operativo: inmutable, sin dependencias de ORM ni de HTTP, y validado
en construccion.

El flujo completo de una regla atraviesa tres validaciones distintas, porque cada
una protege de algo distinto:

    RuleCreate (Pydantic)  -> protege el CONTRATO de la API
      -> Rule (SQLAlchemy) -> protege la INTEGRIDAD de los datos
        -> RuleSpec        -> protege el SISTEMA
          -> argv: ["iptables", "-A", "FWDASH_INPUT", "-s", "1.2.3.4/32", "-j", "DROP"]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

# --------------------------------------------------------------------------- #
# Enumeraciones del dominio
# --------------------------------------------------------------------------- #


class Chain(StrEnum):
    """Cadenas del sistema gestionadas por la aplicacion."""

    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    FORWARD = "FORWARD"


class Table(StrEnum):
    """Tablas de iptables. El MVP solo usa `filter`."""

    FILTER = "filter"


class Action(StrEnum):
    """Targets permitidos para una regla de usuario.

    `LOG` no aparece aqui a proposito: no es una accion que el usuario elija, sino
    una regla adicional que el renderer emite cuando `log_enabled` esta activo
    (fase 2).
    """

    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


class IPVersion(IntEnum):
    """Familia de direcciones.

    El modelo la soporta desde la primera migracion, pero el MVP solo genera
    reglas v4. Añadir v6 sera una implementacion mas del backend (`ip6tables`),
    sin migracion de esquema. Ver docs/ARCHITECTURE.md §9.1.
    """

    V4 = 4
    V6 = 6


class SyncState(StrEnum):
    """Estado de sincronizacion entre la DB y iptables.

    Esta distincion es el corazon del diseño: una regla puede existir en la DB y
    no estar aplicada al sistema.
    """

    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    DRIFT = "drift"


# --------------------------------------------------------------------------- #
# Tipos frontera
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Descripcion completa e inmutable de una regla, lista para renderizar.

    TODO(A3): implementar `__post_init__` llamando a `validators.validate_spec`,
    de modo que sea imposible construir una spec invalida.
    """

    chain: Chain
    action: Action
    protocol: Protocol = Protocol.ALL
    ip_version: int = 4
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    in_interface: str | None = None
    out_interface: str | None = None
    comment: str | None = None
    log_enabled: bool = False
    log_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class Counters:
    """Contadores de paquetes/bytes que iptables mantiene por regla."""

    packets: int = 0
    bytes: int = 0


@dataclass(frozen=True, slots=True)
class NativeRule:
    """Una regla tal y como la reporta iptables, ya parseada.

    Se usa para detectar drift: se compara lo que dice el sistema contra lo que
    dice la base de datos.
    """

    raw: str
    chain: str
    counters: Counters = field(default_factory=Counters)


@dataclass(frozen=True, slots=True)
class ApplyResult:
    """Resultado de una reconciliacion sobre una cadena."""

    chain: Chain
    applied: int = 0
    commands: tuple[tuple[str, ...], ...] = ()
    dry_run: bool = False
