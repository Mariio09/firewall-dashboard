"""Modelo `AuditEvent`: quien hizo que, cuando y con que resultado.

Bloque A5, activo desde el primer dia. Es la tabla que separa 'una app que toca
iptables' de 'una herramienta de seguridad'. Toda mutacion de la politica queda
auditada. Ver docs/ARCHITECTURE.md §2.5."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import ADDRESS_LEN, Base, UtcDateTime, str_enum, utcnow

__all__ = ["AuditAction", "AuditEvent", "AuditResult"]


class AuditAction(StrEnum):
    """Acciones auditadas. Se nombran `<entidad>.<verbo>` para poder filtrar por prefijo."""

    RULE_CREATE = "rule.create"
    RULE_UPDATE = "rule.update"
    RULE_DELETE = "rule.delete"
    RULE_TOGGLE = "rule.toggle"
    RULE_REORDER = "rule.reorder"
    FIREWALL_APPLY = "firewall.apply"
    FIREWALL_PREVIEW = "firewall.preview"
    FIREWALL_TEARDOWN = "firewall.teardown"
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_LOGOUT = "auth.logout"
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"


class AuditResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuditEvent(Base):
    """Un hecho auditable, inmutable por convencion: se inserta, no se edita.

    `auth.login_failed` se registra tambien, y es de los mas utiles: una racha
    de fallos desde una IP es justo el patron que la fase 4 aprendera a detectar.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True, nullable=False)

    #: `SET NULL`: borrar a un usuario no puede borrar la prueba de lo que hizo.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: Copia textual del nombre en el momento del hecho. Si el usuario se borra o
    #: se renombra, la auditoria sigue diciendo quien fue.
    username: Mapped[str | None] = mapped_column(String(50), nullable=True)

    action: Mapped[AuditAction] = mapped_column(
        str_enum(AuditAction, name="audit_action"), nullable=False
    )
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    #: El antes y el despues. Es lo que convierte "alguien cambio una regla" en
    #: "alguien cambio el puerto 22 de DROP a ACCEPT el martes a las 3:14".
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    result: Mapped[AuditResult] = mapped_column(
        str_enum(AuditResult, name="audit_result"), default=AuditResult.SUCCESS, nullable=False
    )
    client_ip: Mapped[str | None] = mapped_column(String(ADDRESS_LEN), nullable=True)
    #: Ata el evento de negocio con la traza tecnica del log de structlog.
    request_id: Mapped[str | None] = mapped_column(String(26), nullable=True)

    __table_args__ = (
        Index("ix_audit_events_action_ts", "action", "ts"),
        Index("ix_audit_events_user_id_ts", "user_id", "ts"),
    )

    def __repr__(self) -> str:
        return f"AuditEvent(action={self.action!r}, user={self.username!r}, result={self.result!r})"
