"""Modelo `Rule`: la entidad central del proyecto.

Bloque A1. La DB es la fuente de verdad; iptables la refleja (ADR-0001).
Campos sensibles al diseño, ver docs/ARCHITECTURE.md §2.2:
  - `uuid`      identificador publico y etiqueta de la regla en iptables
  - `position`  el orden ES la semantica en iptables; unico por cadena
  - `sync_state`  pending | applied | failed | drift
  - `src_ip`    texto normalizado a CIDR por el validador, nunca crudo
  - `src_port`  str, no int: '80' y '8000:8010' son ambos validos"""

from __future__ import annotations

import uuid as uuid_module
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import ADDRESS_LEN, Base, TimestampMixin, UtcDateTime, str_enum
from app.firewall.spec import Action, Chain, IPVersion, Protocol, SyncState, Table

if TYPE_CHECKING:
    from app.models.user import User

__all__ = ["POSITION_STEP", "Rule"]

#: Las posiciones se asignan de 10 en 10. Insertar entre dos reglas contiguas es
#: entonces elegir un hueco, y no renumerar la cadena entera.
POSITION_STEP = 10


def _nuevo_uuid() -> str:
    return str(uuid_module.uuid4())


class Rule(TimestampMixin, Base):
    """Una regla de firewall tal y como la define el usuario.

    Esta fila es la fuente de verdad. Lo que hay en iptables es su reflejo, y
    `sync_state` es la distancia entre ambos: una regla puede existir aqui y no
    estar aplicada todavia. Esa distincion es el corazon del diseño (ADR-0001) y
    lo que la UI muestra en la columna de estado.
    """

    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: Identificador publico. Viaja en la API y viaja tambien dentro de iptables,
    #: en el `--comment` de la regla: es lo que permite volver a atar un contador
    #: (o una linea de log en la fase 2) a la fila que la origino.
    uuid: Mapped[str] = mapped_column(
        String(36), default=_nuevo_uuid, unique=True, index=True, nullable=False
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    #: El PORQUE de la regla. Es el campo que convierte una tabla de IPs en algo
    #: que se puede explicar seis meses despues.
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Que se filtra ------------------------------------------------------ #
    chain: Mapped[Chain] = mapped_column(str_enum(Chain, name="chain"), nullable=False)
    table_name: Mapped[Table] = mapped_column(
        str_enum(Table, name="table_name"), default=Table.FILTER, nullable=False
    )
    ip_version: Mapped[int] = mapped_column(Integer, default=IPVersion.V4, nullable=False)
    action: Mapped[Action] = mapped_column(str_enum(Action, name="action"), nullable=False)
    protocol: Mapped[Protocol] = mapped_column(
        str_enum(Protocol, name="protocol"), default=Protocol.ALL, nullable=False
    )

    #: Siempre normalizado a CIDR por `firewall.validators`. Guardar `1.2.3.4` y
    #: `1.2.3.4/32` como filas distintas romperia la deteccion de drift, que se
    #: hace comparando texto contra la salida de `iptables -S`.
    src_ip: Mapped[str | None] = mapped_column(String(ADDRESS_LEN), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(ADDRESS_LEN), nullable=True)

    #: Texto y no entero: `80` y `8000:8010` son ambos puertos validos en iptables.
    src_port: Mapped[str | None] = mapped_column(String(11), nullable=True)
    dst_port: Mapped[str | None] = mapped_column(String(11), nullable=True)

    in_interface: Mapped[str | None] = mapped_column(String(16), nullable=True)
    out_interface: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # --- Orden y ciclo de vida ---------------------------------------------- #
    #: En iptables el orden ES la semantica: gana la primera regla que hace match.
    #: Por eso la posicion es un campo del modelo y no un detalle de la consulta.
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Desactivar no borra: la regla sigue en la tabla, pero el renderer la omite.

    log_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: 29 caracteres es el limite util real del `--log-prefix` de iptables.
    log_prefix: Mapped[str | None] = mapped_column(String(29), nullable=True)

    #: Bloqueos temporales. La fase 4 (auto-ban) lo usa para caducar reglas solas.
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    # --- Reflejo en el sistema ---------------------------------------------- #
    sync_state: Mapped[SyncState] = mapped_column(
        str_enum(SyncState, name="sync_state"), default=SyncState.PENDING, nullable=False
    )
    #: stderr saneado del ultimo intento fallido. El crudo va al log, no aqui.
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    #: Contadores leidos de `iptables -L -v -n`. BigInteger porque una regla que
    #: lleva meses en una interfaz activa desborda un entero de 32 bits en bytes.
    hit_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    # --- Autoria ------------------------------------------------------------ #
    #: `SET NULL` y no `CASCADE`: borrar a un usuario no puede borrar la politica
    #: de firewall que dejo escrita.
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[User | None] = relationship(back_populates="rules", lazy="selectin")

    __table_args__ = (
        # Dos reglas no pueden ocupar la misma posicion en la misma cadena.
        # OJO al reordenar (A5): un UPDATE masivo que solape posiciones viola
        # esta constraint a mitad de la operacion. La reordenacion se hace en dos
        # fases — desplazar todas las posiciones a un rango alto y luego
        # reasignarlas — o dentro de una transaccion con las posiciones
        # calculadas de forma que no colisionen.
        UniqueConstraint("chain", "position", name="uq_rules_chain_position"),
        CheckConstraint("ip_version IN (4, 6)", name="ip_version_valida"),
        CheckConstraint("position >= 0", name="position_no_negativa"),
        # Coherencia interna: si se pide log, tiene que haber prefijo con el que
        # reconocerlo despues en syslog.
        CheckConstraint("log_enabled = 0 OR log_prefix IS NOT NULL", name="log_requiere_prefijo"),
        Index("ix_rules_chain_position", "chain", "position"),
        Index("ix_rules_sync_state", "sync_state"),
        Index("ix_rules_expires_at", "expires_at"),
    )

    def __repr__(self) -> str:
        return f"Rule(uuid={self.uuid!r}, chain={self.chain!r}, action={self.action!r})"
