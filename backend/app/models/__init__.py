"""Modelos SQLAlchemy: como se guardan los datos.

Este `__init__` es tambien el REGISTRO de modelos: importar el paquete importa
todos los modulos, que es lo que puebla `Base.metadata`. Sin esto, `alembic
revision --autogenerate` no ve las tablas y genera una migracion vacia sin
avisar de nada.

Cada modelo nuevo se añade aqui. Es el unico sitio.
"""

from app.models.alert import Alert, AlertKind, Severity
from app.models.audit_event import AuditAction, AuditEvent, AuditResult
from app.models.packet_log import PacketLog
from app.models.rule import POSITION_STEP, Rule
from app.models.user import Role, User

__all__ = [
    "POSITION_STEP",
    "Alert",
    "AlertKind",
    "AuditAction",
    "AuditEvent",
    "AuditResult",
    "PacketLog",
    "Role",
    "Rule",
    "Severity",
    "User",
]
