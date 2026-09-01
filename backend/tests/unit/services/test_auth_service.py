"""`services/auth_service.py`: login, refresco y RBAC, sin levantar la API.

Que estos tests no necesiten `TestClient` es la prueba de que la regla de
dependencias se sostiene: el servicio no sabe que existe FastAPI.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AuthError, ForbiddenError
from app.core.security import TokenType, create_refresh_token, decode_token, hash_password
from app.models.audit_event import AuditAction, AuditEvent, AuditResult
from app.models.user import Role, User
from app.services import auth_service
from tests.conftest import PASSWORD_DE_PRUEBA


def _eventos(session: Session) -> list[AuditEvent]:
    return list(session.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars())


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #


def test_login_correcto_devuelve_usuario_y_tokens(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    user, tokens = auth_service.login(
        db_session, username="admin", password=PASSWORD_DE_PRUEBA, settings=settings
    )

    assert user.id == admin_user.id
    assert tokens.expires_in == settings.access_token_expire_minutes * 60

    access = decode_token(tokens.access_token, settings=settings)
    assert access.user_id == admin_user.id
    assert access.role == "admin"


def test_login_correcto_actualiza_last_login_at(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    assert admin_user.last_login_at is None

    auth_service.login(db_session, username="admin", password=PASSWORD_DE_PRUEBA, settings=settings)

    db_session.refresh(admin_user)
    assert admin_user.last_login_at is not None
    assert datetime.now(UTC) - admin_user.last_login_at < timedelta(seconds=30)


def test_login_correcto_deja_un_evento_de_auditoria(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    auth_service.login(
        db_session,
        username="admin",
        password=PASSWORD_DE_PRUEBA,
        settings=settings,
        client_ip="192.168.64.10",
        request_id="01J8ZQ4T2N6R7V9WXYZ0ABCDEF",
    )

    evento = _eventos(db_session)[-1]
    assert evento.action is AuditAction.AUTH_LOGIN
    assert evento.result is AuditResult.SUCCESS
    assert evento.user_id == admin_user.id
    assert evento.username == "admin"
    assert evento.client_ip == "192.168.64.10"
    assert evento.request_id == "01J8ZQ4T2N6R7V9WXYZ0ABCDEF"


@pytest.mark.parametrize(
    ("username", "password", "motivo"),
    [
        ("no-existe", PASSWORD_DE_PRUEBA, "unknown_user"),
        ("admin", "la-que-no-es", "bad_password"),
    ],
)
def test_login_fallido_se_audita_con_su_motivo(
    db_session: Session,
    settings: Settings,
    admin_user: User,
    username: str,
    password: str,
    motivo: str,
) -> None:
    with pytest.raises(AuthError):
        auth_service.login(
            db_session,
            username=username,
            password=password,
            settings=settings,
            client_ip="10.0.0.1",
        )

    evento = _eventos(db_session)[-1]
    assert evento.action is AuditAction.AUTH_LOGIN_FAILED
    assert evento.result is AuditResult.FAILURE
    assert evento.username == username
    assert evento.payload["reason"] == motivo
    assert evento.client_ip == "10.0.0.1"


def test_el_mensaje_de_error_no_distingue_los_casos(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    """Si el mensaje cambiara, el login diria que usuarios existen."""
    mensajes = set()
    for username, password in [("no-existe", "x"), ("admin", "x")]:
        with pytest.raises(AuthError) as excinfo:
            auth_service.login(db_session, username=username, password=password, settings=settings)
        mensajes.add(excinfo.value.message)

    assert len(mensajes) == 1


def test_un_usuario_desactivado_no_entra(
    db_session: Session, settings: Settings, crear_usuario: Callable[..., User]
) -> None:
    crear_usuario("suspendido", is_active=False)

    with pytest.raises(AuthError):
        auth_service.login(
            db_session, username="suspendido", password=PASSWORD_DE_PRUEBA, settings=settings
        )

    assert _eventos(db_session)[-1].payload["reason"] == "inactive_user"


def test_el_nombre_se_normaliza_quitando_espacios(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    user, _ = auth_service.login(
        db_session, username="  admin  ", password=PASSWORD_DE_PRUEBA, settings=settings
    )
    assert user.id == admin_user.id


def test_la_contrasena_no_se_normaliza(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    """Recortar espacios en la contraseña reduciria el espacio de busqueda."""
    with pytest.raises(AuthError):
        auth_service.login(
            db_session, username="admin", password=f" {PASSWORD_DE_PRUEBA} ", settings=settings
        )


def test_un_hash_anticuado_se_reescribe_al_entrar(
    db_session: Session, settings: Settings, crear_usuario: Callable[..., User]
) -> None:
    """El login es el unico momento en el que existe la contraseña en claro."""
    from argon2 import PasswordHasher

    user = crear_usuario("antiguo")
    debil = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    user.hashed_password = debil.hash(PASSWORD_DE_PRUEBA)
    db_session.commit()
    viejo = user.hashed_password

    auth_service.login(
        db_session, username="antiguo", password=PASSWORD_DE_PRUEBA, settings=settings
    )

    db_session.refresh(user)
    assert user.hashed_password != viejo
    assert auth_service.login(
        db_session, username="antiguo", password=PASSWORD_DE_PRUEBA, settings=settings
    )


# --------------------------------------------------------------------------- #
# Refresh
# --------------------------------------------------------------------------- #


def test_refresh_devuelve_un_par_nuevo(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    _, tokens = auth_service.login(
        db_session, username="admin", password=PASSWORD_DE_PRUEBA, settings=settings
    )

    user, nuevos = auth_service.refresh(
        db_session, refresh_token=tokens.refresh_token, settings=settings
    )

    assert user.id == admin_user.id
    assert decode_token(nuevos.access_token, settings=settings).user_id == admin_user.id
    assert (
        decode_token(
            nuevos.refresh_token, settings=settings, expected_type=TokenType.REFRESH
        ).user_id
        == admin_user.id
    )


def test_no_se_puede_refrescar_con_un_access_token(
    db_session: Session, settings: Settings, admin_user: User
) -> None:
    _, tokens = auth_service.login(
        db_session, username="admin", password=PASSWORD_DE_PRUEBA, settings=settings
    )

    with pytest.raises(AuthError) as excinfo:
        auth_service.refresh(db_session, refresh_token=tokens.access_token, settings=settings)

    assert excinfo.value.code == "token_wrong_type"


def test_desactivar_la_cuenta_corta_el_refresco(
    db_session: Session, settings: Settings, crear_usuario: Callable[..., User]
) -> None:
    """La mitad util de una revocacion, con el refresco stateless del MVP."""
    user = crear_usuario("temporal", role=Role.OPERATOR)
    token = create_refresh_token(
        user_id=user.id, username=user.username, role=user.role.value, settings=settings
    )

    user.is_active = False
    db_session.commit()

    with pytest.raises(AuthError) as excinfo:
        auth_service.refresh(db_session, refresh_token=token, settings=settings)

    assert excinfo.value.code == "user_inactive"


def test_un_token_de_un_usuario_borrado_no_vale(
    db_session: Session, settings: Settings, crear_usuario: Callable[..., User]
) -> None:
    user = crear_usuario("efimero")
    token = create_refresh_token(
        user_id=user.id, username=user.username, role=user.role.value, settings=settings
    )
    db_session.delete(user)
    db_session.commit()

    with pytest.raises(AuthError) as excinfo:
        auth_service.refresh(db_session, refresh_token=token, settings=settings)

    assert excinfo.value.code == "user_not_found"


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("rol", "minimo", "alcanza"),
    [
        (Role.ADMIN, Role.ADMIN, True),
        (Role.ADMIN, Role.OPERATOR, True),
        (Role.ADMIN, Role.VIEWER, True),
        (Role.OPERATOR, Role.ADMIN, False),
        (Role.OPERATOR, Role.OPERATOR, True),
        (Role.OPERATOR, Role.VIEWER, True),
        (Role.VIEWER, Role.ADMIN, False),
        (Role.VIEWER, Role.OPERATOR, False),
        (Role.VIEWER, Role.VIEWER, True),
    ],
)
def test_la_escalera_de_roles(rol: Role, minimo: Role, alcanza: bool) -> None:
    """Los nueve casos. Con tres roles caben todos, asi que se escriben todos."""
    user = User(username="x", hashed_password=hash_password("x"), role=rol)
    assert auth_service.has_role(user, minimo) is alcanza


def test_ensure_role_explica_que_falta() -> None:
    user = User(username="x", hashed_password=hash_password("x"), role=Role.VIEWER)

    with pytest.raises(ForbiddenError) as excinfo:
        auth_service.ensure_role(user, Role.OPERATOR)

    assert excinfo.value.details == {"required_role": "operator", "current_role": "viewer"}
