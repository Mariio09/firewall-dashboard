"""Dependencias compartidas de FastAPI.

Bloque A1+. Aqui viven dos cosas:

- `build_firewall_backend()`, que devuelve `FakeFirewallBackend` o
  `IptablesBackend` segun `settings.firewall_backend`, y `get_firewall_backend()`,
  que guarda UNA instancia por aplicacion en `app.state`. Esas dos funciones son
  lo que permite correr el MVP completo en el Mac y lo que hace el bloque C casi
  trivial.
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
    "build_firewall_backend",
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


def build_firewall_backend(settings: Settings) -> FirewallBackend:
    """Construye el backend de firewall configurado.

    Estas lineas son la costura entera del proyecto (ADR-0004): con
    `FIREWALL_BACKEND=fake` la aplicacion funciona de punta a punta en el Mac,
    sin VM y sin privilegios, y el bloque C consiste en cambiar esa variable.

    Los parametros de las reglas guardian salen de `settings` y no de los valores
    por defecto del fake: si el `.env` dice que la gestion escucha en el 8080, el
    preview tiene que enseñar el 8080. Un fake configurado distinto que el real
    es justo la clase de mentira contra la que avisa docs/ARCHITECTURE.md §8.

    El import de `SubprocessRunner` es DIFERIDO a proposito. Es el unico modulo
    del proyecto que importa `subprocess`, y con `FIREWALL_BACKEND=fake` no tiene
    por que llegar siquiera a cargarse: el codigo que puede lanzar procesos no
    entra en el proceso mientras nadie lo pida. Cuesta una linea y es defensa en
    profundidad gratis.

    Los fallos de configuracion salen AQUI y no en la primera peticion:
    `SubprocessRunner` valida `iptables_bin` en su constructor (ruta absoluta y
    dentro de la allowlist) y `IptablesBackend` rechaza cualquier tabla que no
    sea `filter`.
    """
    if settings.firewall_backend == "fake":
        return FakeFirewallBackend(
            chain_prefix=settings.managed_chain_prefix,
            management_port=settings.management_port,
            management_cidr=str(settings.management_allowed_cidr),
            management_ssh_port=settings.management_ssh_port,
        )

    from app.firewall.iptables import IptablesBackend
    from app.firewall.runner import SubprocessRunner

    return IptablesBackend(
        SubprocessRunner(use_sudo=settings.use_sudo, iptables_bin=settings.iptables_bin),
        chain_prefix=settings.managed_chain_prefix,
        table=settings.iptables_table,
        management_port=settings.management_port,
        management_cidr=str(settings.management_allowed_cidr),
        management_ssh_port=settings.management_ssh_port,
        timeout=settings.command_timeout_seconds,
    )


def get_firewall_backend(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> FirewallBackend:
    """El backend de ESTA aplicacion, uno solo y compartido entre peticiones.

    Que sea uno solo importa por el fake, que guarda las cadenas en memoria:
    construir uno nuevo por peticion hacia que `POST /firewall/apply` aplicara
    sobre un objeto y `GET /firewall/status` leyera otro, recien nacido y vacio.
    El sintoma habria sido un dashboard que dice "sin aplicar" justo despues de
    aplicar, y la causa no esta a la vista en ninguno de los dos endpoints.

    Vive en `app.state` y no en una variable de modulo a proposito: el ambito
    correcto es la aplicacion, no el proceso. Cada `create_app()` de los tests
    arranca con su firewall limpio sin tener que acordarse de vaciar nada, que
    es la clase de fixture que se olvida y contamina la suite entera.

    El backend real es apatrida —el estado esta en el kernel—, asi que compartirlo
    no cambia nada para el; el `lifespan` construye el mismo objeto por el mismo
    camino, y aqui queda la construccion perezosa para quien monte la aplicacion
    sin ciclo de vida (un `TestClient` sin `with`).
    """
    backend: FirewallBackend | None = getattr(request.app.state, "firewall", None)
    if backend is None:
        backend = build_firewall_backend(settings)
        backend.ensure_scaffold()
        request.app.state.firewall = backend
    return backend


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
