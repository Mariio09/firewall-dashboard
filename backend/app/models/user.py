"""Modelo `User` con RBAC de tres roles: admin | operator | viewer.

Bloque A4. Tres roles es el minimo que hace que el RBAC signifique algo;
con dos parece decorativo."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UtcDateTime, str_enum

if TYPE_CHECKING:
    from app.models.rule import Rule

__all__ = ["Role", "User"]


class Role(StrEnum):
    """Roles del RBAC, de mayor a menor privilegio.

    Vive aqui y no en `firewall/spec.py` porque no es un concepto de red: la
    capa de firewall no sabe que existen los usuarios.
    """

    ADMIN = "admin"
    """Todo lo del operador, mas la gestion de usuarios."""

    OPERATOR = "operator"
    """Crea, edita y aplica reglas. Es el rol de trabajo."""

    VIEWER = "viewer"
    """Solo lectura. Util para enseñar el dashboard sin poder tocar nada."""


class User(TimestampMixin, Base):
    """Una cuenta con acceso al dashboard."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)

    #: Argon2id (`argon2-cffi`). Nunca la contraseña, obviamente; y el nombre del
    #: campo lo dice para que nadie lo confunda al leer un log.
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    role: Mapped[Role] = mapped_column(
        str_enum(Role, name="role"), default=Role.VIEWER, nullable=False
    )
    #: Desactivar en vez de borrar: mantiene la autoria de las reglas ya creadas
    #: y deja rastro en la auditoria.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    last_login_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    rules: Mapped[list[Rule]] = relationship(back_populates="created_by", lazy="selectin")

    def __repr__(self) -> str:
        return f"User(username={self.username!r}, role={self.role!r})"
