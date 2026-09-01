"""Modelo `PacketLog`: paquetes registrados por el target LOG de iptables.

FASE 2. La tabla se crea ya (para no migrar esquema despues) pero permanece
vacia durante el MVP.

Decision: `rule_uuid` va SIN foreign key. Un log es un hecho historico y debe
sobrevivir al borrado de la regla que lo genero. Ver docs/ARCHITECTURE.md §2.3."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import ADDRESS_LEN, Base, utcnow

__all__ = ["PacketLog"]


class PacketLog(Base):
    """Una linea de `journalctl` producida por una regla con target LOG.

    No hereda `TimestampMixin`: aqui la marca de tiempo que importa es `ts`, la
    del paquete, no la del INSERT. Distinguirlas evita que un retraso del worker
    desplace las graficas.
    """

    __tablename__ = "packet_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True, nullable=False
    )

    src_ip: Mapped[str | None] = mapped_column(String(ADDRESS_LEN), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(ADDRESS_LEN), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    in_interface: Mapped[str | None] = mapped_column(String(16), nullable=True)

    #: Extraido del `--log-prefix` (`FWD:<uuid8>`). Deliberadamente SIN clave
    #: foranea: con FK, borrar una regla o perderia sus logs o quedaria
    #: bloqueado. Un log es historia, y la historia no se edita.
    rule_uuid: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)

    #: Linea original de syslog. Es lo que permite depurar el parser cuando
    #: aparezca un formato que no habiamos previsto.
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # Los tres indices son exactamente las tres consultas de las graficas de
        # la fase 3 (top de IPs, puertos mas golpeados, linea temporal). Crearlos
        # ahora es gratis; crearlos con la tabla llena, no.
        Index("ix_packet_logs_src_ip_ts", "src_ip", "ts"),
        Index("ix_packet_logs_dst_port_ts", "dst_port", "ts"),
    )

    def __repr__(self) -> str:
        return f"PacketLog(ts={self.ts!r}, src_ip={self.src_ip!r}, dst_port={self.dst_port!r})"
