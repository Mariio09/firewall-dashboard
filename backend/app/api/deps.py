"""Dependencias compartidas de FastAPI.

Bloque A1+. Aqui viven dos cosas:

- `get_firewall_backend()`, que devuelve `FakeFirewallBackend` o `IptablesBackend`
  segun `settings.firewall_backend`. Esa unica funcion es lo que permite correr el
  MVP completo en el Mac y lo que hace el bloque C casi trivial.
- El RBAC (A4): `CurrentUser` resuelve el token en usuario, y `require_role()`
  fabrica la dependencia que exige un rol minimo. Un endpoint protegido se escribe
  poniendo `RequireOperator` en la firma, y no hay ninguna otra forma de hacerlo:
  la comprobacion no puede quedarse a medias dentro del handler."""

from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import AuthError
from app.db.session import get_session
from app.firewall.base import FirewallBackend
from app.firewall.fake import FakeFirewallBackend
from app.models.user import Role, User
from app.services import auth_service

__all__ = [
    "ClientIp",
    "CurrentSettings",
    "CurrentUser",
    "DbSession",
    "Firewall",
    "RequestId",
    "RequireAdmin",
    "RequireOperator",
    "RequireViewer",
    "get_client_ip",
    "get_current_user",
    "get_db",
    "get_firewall_backend",
    "get_request_id",
    "require_role",
]

#: `auto_error=False` para que un token ausente entre por nuestra jerarquia de
#: errores y no por el 403 que FastAPI devuelve por su cuenta. Sin esto, "no has
#: mandado token" saldria como 403 con un cuerpo distinto al del resto de la API.
bearer_scheme = HTTPBearer(auto_error=False, description="Access token JWT.")


def get_db() -> Generator[Session, None, None]:
    """Una sesion de base de datos por peticion."""
    yield from get_session()


def get_settings_dep() -> Settings:
    """La configuracion, como dependencia inyectable.

    Pedirla por inyeccion en vez de llamar a `get_settings()` dentro del handler
    permite sobreescribirla en los tests con `dependency_overrides`.
    """
    return get_settings()


def get_request_id(request: Request) -> str | None:
    """Identificador de la peticion actual, puesto por el middleware."""
    return getattr(request.state, "request_id", None)


def get_client_ip(request: Request) -> str | None:
    """IP de origen, para la auditoria.

    Se lee de la conexion y NO de `X-Forwarded-For`: esa cabecera la pone
    cualquiera que sepa escribirla, y una auditoria que se puede falsificar
    desde el propio cliente no vale nada. El dia que haya un proxy delante
    habra que decidir en quien se confia, y sera un cambio consciente aqui.
    """
    return request.client.host if request.client else None


def get_firewall_backend(
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> FirewallBackend:
    """Devuelve el backend de firewall configurado.

    Estas seis lineas son la costura entera del proyecto (ADR-0004): con
    `FIREWALL_BACKEND=fake` la aplicacion funciona de punta a punta en el Mac,
    sin VM y sin privilegios, y el bloque C consiste en cambiar esa variable.

    `IptablesBackend` necesita un `CommandRunner` real, que es el bloque B2. Se
    construye ahi, no aqui, para no arrastrar `subprocess` a un import que
    ocurre tambien en el Mac.
    """
    if settings.firewall_backend == "fake":
        return FakeFirewallBackend()

    # TODO(B2/B3): construir SubprocessRunner + IptablesBackend con los valores
    # de `settings` (iptables_bin, use_sudo, timeout, prefijo de cadena y los
    # parametros de las reglas guardian).
    raise NotImplementedError(
        "El backend 'iptables' se implementa en el bloque B. "
        "Usa FIREWALL_BACKEND=fake mientras tanto."
    )


DbSession = Annotated[Session, Depends(get_db)]
CurrentSettings = Annotated[Settings, Depends(get_settings_dep)]
Firewall = Annotated[FirewallBackend, Depends(get_firewall_backend)]


# --------------------------------------------------------------------------- #
# Identidad y roles (A4)
# --------------------------------------------------------------------------- #


def get_current_user(
    session: DbSession,
    settings: CurrentSettings,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> User:
    """El usuario detras del `Authorization: Bearer <token>` de esta peticion.

    Delega en `auth_service`, que es quien decide que es un token valido; aqui
    solo se saca de la cabecera. Cada peticion relee el usuario de la base de
    datos, asi que desactivar una cuenta o cambiarle el rol surte efecto en la
    siguiente peticion y no cuando caduque el token.
    """
    if credentials is None or not credentials.credentials:
        raise AuthError("Falta la cabecera Authorization con un token Bearer.")
    return auth_service.resolve_user_from_token(
        session, token=credentials.credentials, settings=settings
    )


CurrentUser = Annotated[User, Depends(get_current_user)]
RequestId = Annotated[str | None, Depends(get_request_id)]
ClientIp = Annotated[str | None, Depends(get_client_ip)]


def require_role(minimo: Role) -> Callable[[User], User]:
    """Fabrica una dependencia que exige un rol minimo.

    Devuelve el usuario para que el handler pueda usarlo sin pedirlo dos veces:

        @router.post("/rules")
        def crear(usuario: RequireOperator) -> RuleRead: ...

    La alternativa —comprobar el rol dentro del handler— funciona igual de bien
    hasta el dia en que a alguien se le olvida en un endpoint nuevo. Aqui, si
    falta la anotacion, el endpoint no compila con un usuario dentro.
    """

    def dependencia(user: CurrentUser) -> User:
        auth_service.ensure_role(user, minimo)
        return user

    return dependencia


#: Los tres roles, ya listos para poner en una firma. `RequireViewer` no es
#: redundante: significa "hay que estar autenticado", que es distinto de "es
#: publico" y se lee mejor que un `CurrentUser` suelto.
RequireViewer = Annotated[User, Depends(require_role(Role.VIEWER))]
RequireOperator = Annotated[User, Depends(require_role(Role.OPERATOR))]
RequireAdmin = Annotated[User, Depends(require_role(Role.ADMIN))]
