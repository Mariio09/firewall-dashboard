"""Los tres endpoints de auth, por HTTP, con la aplicacion entera montada.

Lo que se prueba aqui y no en el test del servicio: el codigo de estado, la
forma del error (el sobre unico que espera el frontend) y que la cabecera
`Authorization` se lee como debe.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import RequireAdmin, RequireOperator, RequireViewer
from app.core.config import Settings
from app.core.security import create_refresh_token
from app.models.audit_event import AuditAction, AuditEvent
from app.models.user import Role, User
from tests.conftest import PASSWORD_DE_PRUEBA

LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
ME = "/api/v1/auth/me"


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #


def test_login_devuelve_los_dos_tokens(client: TestClient, admin_user: User) -> None:
    respuesta = client.post(LOGIN, json={"username": "admin", "password": PASSWORD_DE_PRUEBA})

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert cuerpo["token_type"] == "bearer"
    assert cuerpo["expires_in"] == 30 * 60
    assert cuerpo["access_token"] and cuerpo["refresh_token"]
    assert cuerpo["access_token"] != cuerpo["refresh_token"]


def test_el_token_recien_emitido_sirve_para_entrar(client: TestClient, admin_user: User) -> None:
    """El recorrido completo: login -> usar el token -> /me. Es el flujo del frontend."""
    tokens = client.post(LOGIN, json={"username": "admin", "password": PASSWORD_DE_PRUEBA}).json()

    respuesta = client.get(ME, headers={"Authorization": f"Bearer {tokens['access_token']}"})

    assert respuesta.status_code == 200
    assert respuesta.json()["username"] == "admin"


def test_login_con_credenciales_malas_da_401_con_el_sobre_de_siempre(
    client: TestClient, admin_user: User
) -> None:
    respuesta = client.post(LOGIN, json={"username": "admin", "password": "no"})

    assert respuesta.status_code == 401
    error = respuesta.json()["error"]
    assert error["code"] == "unauthorized"
    assert error["request_id"]
    assert "incorrectos" in error["message"]


def test_login_no_filtra_si_el_usuario_existe(client: TestClient, admin_user: User) -> None:
    existe = client.post(LOGIN, json={"username": "admin", "password": "no"})
    no_existe = client.post(LOGIN, json={"username": "fantasma", "password": "no"})

    assert existe.status_code == no_existe.status_code
    assert existe.json()["error"]["message"] == no_existe.json()["error"]["message"]


def test_login_sin_campos_da_422(client: TestClient) -> None:
    respuesta = client.post(LOGIN, json={"username": "admin"})

    assert respuesta.status_code == 422
    assert respuesta.json()["error"]["code"] == "validation_error"


def test_la_respuesta_no_contiene_el_hash(client: TestClient, admin_user: User) -> None:
    respuesta = client.post(LOGIN, json={"username": "admin", "password": PASSWORD_DE_PRUEBA})
    assert "hashed_password" not in respuesta.text
    assert "argon2" not in respuesta.text


def test_el_login_por_http_queda_auditado(
    client: TestClient, db_session: Session, admin_user: User
) -> None:
    client.post(LOGIN, json={"username": "admin", "password": PASSWORD_DE_PRUEBA})

    evento = db_session.execute(
        select(AuditEvent).where(AuditEvent.action == AuditAction.AUTH_LOGIN)
    ).scalar_one()
    assert evento.username == "admin"
    # `TestClient` se presenta con esta IP; lo que importa es que se guarda una.
    assert evento.client_ip == "testclient"
    assert evento.request_id


# --------------------------------------------------------------------------- #
# Refresh
# --------------------------------------------------------------------------- #


def test_refresh_devuelve_un_par_nuevo(client: TestClient, admin_user: User) -> None:
    tokens = client.post(LOGIN, json={"username": "admin", "password": PASSWORD_DE_PRUEBA}).json()

    respuesta = client.post(REFRESH, json={"refresh_token": tokens["refresh_token"]})

    assert respuesta.status_code == 200
    assert respuesta.json()["access_token"]


def test_refresh_con_un_access_token_da_401(client: TestClient, admin_user: User) -> None:
    tokens = client.post(LOGIN, json={"username": "admin", "password": PASSWORD_DE_PRUEBA}).json()

    respuesta = client.post(REFRESH, json={"refresh_token": tokens["access_token"]})

    assert respuesta.status_code == 401
    assert respuesta.json()["error"]["code"] == "token_wrong_type"


def test_refresh_con_basura_da_401(client: TestClient) -> None:
    respuesta = client.post(REFRESH, json={"refresh_token": "esto.no.es"})

    assert respuesta.status_code == 401
    assert respuesta.json()["error"]["code"] == "token_invalid"


# --------------------------------------------------------------------------- #
# /me
# --------------------------------------------------------------------------- #


def test_me_devuelve_al_usuario_sin_su_hash(
    client: TestClient, admin_user: User, auth_headers: dict[str, str]
) -> None:
    respuesta = client.get(ME, headers=auth_headers)

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert cuerpo == {
        "id": admin_user.id,
        "username": "admin",
        "email": None,
        "role": "admin",
        "is_active": True,
        "created_at": cuerpo["created_at"],
        "last_login_at": None,
    }


def test_me_sin_cabecera_da_401(client: TestClient) -> None:
    """Y no el 403 que FastAPI devolveria por su cuenta con `HTTPBearer`."""
    respuesta = client.get(ME)

    assert respuesta.status_code == 401
    assert respuesta.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(
    "cabecera",
    ["", "Bearer", "Bearer ", "Basic abc", "Bearer no.es.un.token"],
)
def test_me_con_una_cabecera_rara_da_401(client: TestClient, cabecera: str) -> None:
    respuesta = client.get(ME, headers={"Authorization": cabecera})
    assert respuesta.status_code == 401


def test_me_con_un_refresh_token_da_401(
    client: TestClient, admin_user: User, settings: Settings
) -> None:
    """El refresh dura siete dias: si valiera aqui, el access token sobraria."""
    refresh = create_refresh_token(
        user_id=admin_user.id, username="admin", role="admin", settings=settings
    )

    respuesta = client.get(ME, headers={"Authorization": f"Bearer {refresh}"})

    assert respuesta.status_code == 401
    assert respuesta.json()["error"]["code"] == "token_wrong_type"


def test_desactivar_a_alguien_le_echa_en_la_siguiente_peticion(
    client: TestClient,
    db_session: Session,
    admin_user: User,
    auth_headers: dict[str, str],
) -> None:
    """El usuario se relee en cada peticion; el token no es un salvoconducto."""
    assert client.get(ME, headers=auth_headers).status_code == 200

    admin_user.is_active = False
    db_session.commit()

    respuesta = client.get(ME, headers=auth_headers)
    assert respuesta.status_code == 401
    assert respuesta.json()["error"]["code"] == "user_inactive"


# --------------------------------------------------------------------------- #
# RBAC: los tres candados, sobre endpoints de mentira
# --------------------------------------------------------------------------- #


@pytest.fixture
def client_rbac(api_app: FastAPI) -> Iterator[TestClient]:
    """Aplicacion de prueba con un endpoint por rol.

    Se montan aqui y no en la API real porque lo que se prueba es la
    dependencia, no un endpoint concreto: cuando A5 añada `/rules`, estos tests
    siguen valiendo sin tocarlos.
    """

    @api_app.get("/_test/viewer")
    def solo_autenticados(usuario: RequireViewer) -> dict[str, str]:
        return {"username": usuario.username}

    @api_app.get("/_test/operator")
    def solo_operadores(usuario: RequireOperator) -> dict[str, str]:
        return {"username": usuario.username}

    @api_app.get("/_test/admin")
    def solo_admins(usuario: RequireAdmin) -> dict[str, str]:
        return {"username": usuario.username}

    with TestClient(api_app) as test_client:
        yield test_client


@pytest.mark.parametrize(
    ("rol", "ruta", "esperado"),
    [
        (Role.VIEWER, "/_test/viewer", 200),
        (Role.VIEWER, "/_test/operator", 403),
        (Role.VIEWER, "/_test/admin", 403),
        (Role.OPERATOR, "/_test/viewer", 200),
        (Role.OPERATOR, "/_test/operator", 200),
        (Role.OPERATOR, "/_test/admin", 403),
        (Role.ADMIN, "/_test/viewer", 200),
        (Role.ADMIN, "/_test/operator", 200),
        (Role.ADMIN, "/_test/admin", 200),
    ],
)
def test_cada_rol_llega_hasta_donde_le_toca(
    client_rbac: TestClient,
    crear_usuario: Callable[..., User],
    headers_de: Callable[[User], dict[str, str]],
    rol: Role,
    ruta: str,
    esperado: int,
) -> None:
    usuario = crear_usuario(f"usuario-{rol.value}", role=rol)

    respuesta = client_rbac.get(ruta, headers=headers_de(usuario))

    assert respuesta.status_code == esperado


def test_un_403_dice_que_rol_hacia_falta(
    client_rbac: TestClient,
    viewer_user: User,
    headers_de: Callable[[User], dict[str, str]],
) -> None:
    respuesta = client_rbac.get("/_test/admin", headers=headers_de(viewer_user))

    error = respuesta.json()["error"]
    assert error["code"] == "forbidden"
    assert error["details"] == {"required_role": "admin", "current_role": "viewer"}


def test_sin_token_es_401_y_no_403(client_rbac: TestClient) -> None:
    """La diferencia importa: 401 es "identificate", 403 es "no te alcanza"."""
    assert client_rbac.get("/_test/viewer").status_code == 401
