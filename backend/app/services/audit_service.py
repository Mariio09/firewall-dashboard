"""Registro de eventos de auditoria.

Escrito en A4 con lo justo que necesita la autenticacion; A5 lo reutiliza tal
cual para las mutaciones de reglas. Es la tabla que separa "una app que toca
iptables" de "una herramienta de seguridad".

Dos invariantes de este modulo:

1. **Un evento de auditoria no puede tumbar la operacion que audita.** Si el
   INSERT falla, se loguea y se sigue: perder el rastro de un login correcto es
   malo, pero impedir el login por no poder escribirlo es peor.
2. **Nada de secretos en `payload`.** Ni tokens, ni contraseñas, ni hashes. El
   payload se enseña entero en el dashboard.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.audit_event import AuditAction, AuditEvent, AuditResult
from app.models.user import User

__all__ = ["record"]

logger = get_logger(__name__)

#: Claves que jamas deben acabar en la columna `payload`. La lista es corta a
#: proposito: es una red de seguridad contra un descuido, no un sanitizador.
_CLAVES_PROHIBIDAS = frozenset(
    {"password", "hashed_password", "token", "access_token", "refresh_token", "secret"}
)


def record(
    session: Session,
    *,
    action: AuditAction,
    result: AuditResult = AuditResult.SUCCESS,
    user: User | None = None,
    username: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    payload: dict[str, Any] | None = None,
    client_ip: str | None = None,
    request_id: str | None = None,
    commit: bool = False,
) -> AuditEvent | None:
    """Inserta un evento en `audit_events`.

    `username` se guarda ademas del `user_id` y se copia del usuario cuando hay
    uno: si mañana se borra la cuenta, el `SET NULL` de la clave foranea deja el
    evento sin `user_id`, pero el nombre sigue ahi. En un `auth.login_failed` es
    justo al reves —no hay usuario, solo el nombre que se intento—, y por eso el
    parametro existe por separado.

    Devuelve `None` si el registro no se pudo escribir. Quien llama no deberia
    comprobarlo: no hay nada sensato que hacer con esa informacion.
    """
    limpio = {k: v for k, v in (payload or {}).items() if k.lower() not in _CLAVES_PROHIBIDAS}

    evento = AuditEvent(
        user_id=user.id if user is not None else None,
        username=username or (user.username if user is not None else None),
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        payload=limpio,
        result=result,
        client_ip=client_ip,
        request_id=request_id,
    )

    try:
        session.add(evento)
        session.flush()
        if commit:
            session.commit()
    except SQLAlchemyError as exc:
        # `rollback` y no `remove`: tras un error la sesion queda inutilizable
        # hasta que se revierte, y quien llama probablemente tenga aun trabajo
        # que confirmar.
        session.rollback()
        logger.error("auditoria_no_registrada", action=action.value, exc_info=exc)
        return None

    return evento
