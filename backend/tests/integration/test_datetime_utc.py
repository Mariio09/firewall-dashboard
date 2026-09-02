"""Los datetime salen de la base de datos y de la API con zona horaria.

Estos tests existen por un bug concreto encontrado en el recorrido manual de A4:
`/auth/me` devolvia `"2026-09-01T22:08:13.179259"`, sin `Z` ni offset, porque
SQLite no guarda la zona aunque la columna se declare `DateTime(timezone=True)`.
En JavaScript ese literal se interpreta como hora LOCAL, asi que en Madrid toda
fecha de la API llegaba al navegador con dos horas de adelanto.

Es un bug silencioso: no rompe nada, solo desplaza las graficas. Por eso se fija
con tests y no solo con el `UtcDateTime` de `db/base.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from app.models.audit_event import AuditAction, AuditEvent
from app.models.user import User

#: Una zona con offset distinto de UTC y sin horario de verano, para que el test
#: de por si igual en enero que en agosto.
KATMANDU = timezone(timedelta(hours=5, minutes=45), name="Asia/Katmandu")


def test_un_datetime_vuelve_de_la_db_con_tzinfo(db_session: Session) -> None:
    """El caso que fallaba: lo que se lee tiene zona, no es ingenuo."""
    evento = AuditEvent(action=AuditAction.AUTH_LOGIN, username="alguien")
    db_session.add(evento)
    db_session.commit()

    # `expire_on_commit=False` deja en memoria el objeto Python original, que
    # siempre tuvo tzinfo. Hay que expulsarlo para forzar una lectura real de
    # SQLite, que es donde se perdia la zona.
    db_session.expire(evento)

    assert evento.ts.tzinfo is not None
    assert evento.ts.utcoffset() == timedelta(0)


def test_guardar_en_otra_zona_normaliza_a_utc(db_session: Session) -> None:
    """Todo se guarda en UTC, venga en la zona que venga.

    Sin esto, dos filas escritas por clientes en husos distintos no se podrian
    ordenar entre si: el texto que guarda SQLite es la hora de pared, sin offset.
    """
    momento = datetime(2026, 9, 1, 12, 0, tzinfo=KATMANDU)
    evento = AuditEvent(action=AuditAction.AUTH_LOGIN, username="alguien", ts=momento)
    db_session.add(evento)
    db_session.commit()
    db_session.expire(evento)

    assert evento.ts == momento  # el mismo instante...
    assert evento.ts.utcoffset() == timedelta(0)  # ...expresado en UTC
    assert evento.ts.hour == 6
    assert evento.ts.minute == 15


def test_un_datetime_ingenuo_se_rechaza_al_guardar(db_session: Session) -> None:
    """Escribir sin zona falla en el acto en vez de desfasar en silencio.

    Suponerle UTC seria volver al bug: un naive puede venir de `datetime.now()`
    —hora local del servidor— o de un ISO sin offset, y no hay forma de saber
    cual. La entrada del usuario no llega aqui sin zona: los schemas la
    normalizan antes, para que un cliente despistado reciba un 422 y no un 500.
    """
    evento = AuditEvent(
        action=AuditAction.AUTH_LOGIN,
        username="alguien",
        ts=datetime(2026, 9, 1, 12, 0),  # ingenuo a proposito: es el caso malo
    )
    db_session.add(evento)

    with pytest.raises((StatementError, ValueError)) as error:
        db_session.flush()

    assert "sin zona horaria" in str(error.value)
    db_session.rollback()


def test_la_api_serializa_las_fechas_con_offset(
    client: TestClient, admin_user: User, auth_headers: dict[str, str]
) -> None:
    """El contrato con el frontend: `new Date(...)` no puede adivinar la zona.

    Se comprueba en `/auth/me` porque es el endpoint donde se detecto, pero lo
    que se esta verificando es el tipo de columna, que vale para todos.
    """
    respuesta = client.get("/api/v1/auth/me", headers=auth_headers)

    assert respuesta.status_code == 200
    created_at: str = respuesta.json()["created_at"]
    assert created_at.endswith("Z") or "+00:00" in created_at, (
        f"La fecha viaja sin zona horaria: {created_at!r}. El navegador la leera como hora local."
    )
    # Y ademas se puede volver a leer como el instante correcto.
    leida = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    assert abs(leida - datetime.now(UTC)) < timedelta(minutes=5)
