"""Modelo `Alert`: deteccion de patrones sospechosos.

FASE 4. Tabla creada, sin uso en el MVP."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import ADDRESS_LEN, Base, str_enum, utcnow

__all__ = ["Alert", "AlertKind", "Severity"]


class AlertKind(StrEnum):
    """Patrones que el detector de la fase 4 sabe reconocer."""

    BRUTE_FORCE = "brute_force"
    """Muchos intentos contra un mismo puerto (22, 3389...)."""

    PORT_SCAN = "port_scan"
    """Una misma IP tocando muchos puertos distintos."""

    RATE_LIMIT = "rate_limit"
    """Volumen anomalo desde un origen concreto."""


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(Base):
    """Una deteccion, con su contexto y su acuse de recibo."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True, nullable=False
    )

    kind: Mapped[AlertKind] = mapped_column(str_enum(AlertKind, name="alert_kind"), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        str_enum(Severity, name="severity"), default=Severity.MEDIUM, nullable=False
    )

    src_ip: Mapped[str | None] = mapped_column(String(ADDRESS_LEN), nullable=True)

    #: Evidencia de la deteccion: ventana, umbral, muestras. JSON porque la forma
    #: depende de `kind` y no merece una tabla por tipo de alerta.
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    #: Como en `packet_logs`, sin FK: la alerta sobrevive a la regla.
    related_rule_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True)

    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (Index("ix_alerts_kind_ts", "kind", "ts"),)

    def __repr__(self) -> str:
        return f"Alert(kind={self.kind!r}, severity={self.severity!r}, src_ip={self.src_ip!r})"
