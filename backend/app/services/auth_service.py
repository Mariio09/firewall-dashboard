"""Autenticacion, emision de tokens y comprobaciones de rol.

Bloque A4. Aqui esta la logica; `api/v1/auth.py` solo traduce HTTP y
`api/deps.py` solo inyecta. Este modulo no importa `fastapi` (lo comprueba
`tests/unit/test_architecture.py`): lanza excepciones de dominio y se puede
probar entero con una sesion de SQLite en memoria y ni una peticion HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AuthError, ForbiddenError
from app.core.logging import get_logger
from app.core.security import (
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
    waste_time_like_a_verification,
)
from app.db.base import utcnow
from app.models.audit_event import AuditAction, AuditResult
from app.models.user import Role, User
from app.services import audit_service

__all__ = [
    "IssuedTokens",
    "ensure_role",
    "has_role",
    "login",
    "refresh",
    "resolve_user_from_token",
]

logger = get_logger(__name__)

#: Los roles ordenados. Un diccionario y no `IntEnum` porque el valor que se
#: guarda en la base de datos y viaja por la API es el texto (`"operator"`), y
#: mezclar las dos cosas en el mismo tipo termina en un `role=1` en un JSON.
_RANGO: dict[Role, int] = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}

#: Mismo mensaje para "no existe" y "contraseña incorrecta". Distinguirlos
#: convierte el login en un oraculo que responde si un usuario existe.
_CREDENCIALES_INVALIDAS = "Usuario o contraseña incorrectos."


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    """Un par de tokens recien emitido.

    Es una dataclass y no el schema `TokenPair` para que este modulo no dependa
    de la capa de presentacion: el router construye el schema a partir de esto.
    """

    access_token: str
    refresh_token: str
    expires_in: int


# --------------------------------------------------------------------------- #
# Emision
# --------------------------------------------------------------------------- #


def _emitir(user: User, settings: Settings) -> IssuedTokens:
    """Access + refresh para un usuario ya autenticado.

    Los tres argumentos se repiten en vez de empaquetarlos en un `**kwargs`
    comun: un diccionario suelto le quita el tipo a cada parametro y mypy deja
    de poder comprobar la llamada, que es justo lo que se quiere aqui.
    """
    return IssuedTokens(
        access_token=create_access_token(
            user_id=user.id, username=user.username, role=user.role.value, settings=settings
        ),
        refresh_token=create_refresh_token(
            user_id=user.id, username=user.username, role=user.role.value, settings=settings
        ),
        expires_in=settings.access_token_expire_minutes * 60,
    )


def _buscar_por_nombre(session: Session, username: str) -> User | None:
    return session.execute(select(User).where(User.username == username)).scalar_one_or_none()


def _cargar_usuario_activo(session: Session, user_id: int) -> User:
    """El usuario del token, si todavia puede entrar.

    Se relee de la base de datos en cada peticion en vez de fiarse de los claims
    del token. Cuesta una consulta, y a cambio desactivar una cuenta surte
    efecto **ya**, y no cuando caduque su access token. Lo mismo vale para un
    cambio de rol: un `viewer` ascendido a `operator` no tiene que volver a
    hacer login, y —lo que importa— uno degradado no conserva sus permisos
    durante media hora.
    """
    user = session.get(User, user_id)
    if user is None:
        raise AuthError("La cuenta ya no existe.", code="user_not_found")
    if not user.is_active:
        raise AuthError("La cuenta esta desactivada.", code="user_inactive")
    return user


# --------------------------------------------------------------------------- #
# Casos de uso
# --------------------------------------------------------------------------- #


def _rechazar(
    session: Session,
    nombre: str,
    motivo: str,
    client_ip: str | None,
    request_id: str | None,
) -> NoReturn:
    """Deja rastro del intento fallido y corta con un 401 generico.

    Es una funcion aparte —y no un `raise` en cada rama— por dos motivos: el
    mensaje al cliente se escribe UNA vez, asi que no puede acabar filtrando el
    motivo real por descuido, y su tipo `NoReturn` le dice a mypy que despues de
    llamarla el usuario ya no puede ser `None`, sin necesidad de un `assert`.

    El evento se atribuye al nombre intentado y nunca al usuario: no llego a
    abrirse ninguna sesion, y colgar un fallo de la cuenta de alguien que quiza
    no ha hecho nada seria contar otra historia.
    """
    audit_service.record(
        session,
        action=AuditAction.AUTH_LOGIN_FAILED,
        result=AuditResult.FAILURE,
        username=nombre,
        payload={"reason": motivo},
        client_ip=client_ip,
        request_id=request_id,
        commit=True,
    )
    logger.warning("login_fallido", username=nombre, reason=motivo, client_ip=client_ip)
    raise AuthError(_CREDENCIALES_INVALIDAS)


def login(
    session: Session,
    *,
    username: str,
    password: str,
    settings: Settings,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> tuple[User, IssuedTokens]:
    """Comprueba las credenciales, deja rastro y devuelve el par de tokens.

    Todo intento fallido se registra como `auth.login_failed`, con el nombre que
    se intento y la IP de origen. No es burocracia: una racha de fallos desde
    una misma IP es exactamente el patron que la deteccion de la fase 4 quiere
    encontrar, y para entonces los datos ya tienen que estar ahi.
    """
    nombre = username.strip()
    user = _buscar_por_nombre(session, nombre)

    if user is None:
        # Gastar el mismo tiempo que una verificacion real: sin esto, el tiempo
        # de respuesta dice si el usuario existe.
        waste_time_like_a_verification()
        _rechazar(session, nombre, "unknown_user", client_ip, request_id)
    if not user.is_active:
        waste_time_like_a_verification()
        _rechazar(session, nombre, "inactive_user", client_ip, request_id)
    if not verify_password(password, user.hashed_password):
        _rechazar(session, nombre, "bad_password", client_ip, request_id)

    # Es el unico instante en el que existe la contraseña en claro, asi que es
    # el unico en el que se puede reescribir un hash con parametros anticuados.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)
        logger.info("hash_actualizado", username=user.username)

    user.last_login_at = utcnow()
    tokens = _emitir(user, settings)

    audit_service.record(
        session,
        action=AuditAction.AUTH_LOGIN,
        user=user,
        client_ip=client_ip,
        request_id=request_id,
    )
    session.commit()
    logger.info("login_correcto", username=user.username, role=user.role.value)
    return user, tokens


def refresh(
    session: Session, *, refresh_token: str, settings: Settings
) -> tuple[User, IssuedTokens]:
    """Cambia un token de refresco valido por un par nuevo.

    El refresco es **stateless** en el MVP: no hay tabla de tokens, asi que un
    refresh robado sirve hasta que caduca y `/logout` no puede invalidar nada
    (ADR-0008). Lo que si se comprueba en cada refresco es el estado de la
    cuenta: desactivar un usuario corta su renovacion al instante, que es la
    mitad util de una revocacion.
    """
    payload = decode_token(refresh_token, settings=settings, expected_type=TokenType.REFRESH)
    user = _cargar_usuario_activo(session, payload.user_id)
    return user, _emitir(user, settings)


def resolve_user_from_token(session: Session, *, token: str, settings: Settings) -> User:
    """El usuario detras de un access token. Lo usa `api/deps.py` en cada peticion."""
    payload = decode_token(token, settings=settings, expected_type=TokenType.ACCESS)
    return _cargar_usuario_activo(session, payload.user_id)


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #


def has_role(user: User, minimo: Role) -> bool:
    """¿Alcanza el rol del usuario el minimo pedido?

    Los roles son una escalera, no un conjunto de permisos: `admin` puede todo
    lo de `operator`, y `operator` todo lo de `viewer`. Con tres roles y un
    dominio pequeño, un sistema de permisos granulares seria mas codigo del que
    hay que proteger.
    """
    return _RANGO[user.role] >= _RANGO[minimo]


def ensure_role(user: User, minimo: Role) -> None:
    """Igual que `has_role`, pero corta la peticion con un 403."""
    if not has_role(user, minimo):
        raise ForbiddenError(
            f"Esta operacion requiere el rol '{minimo.value}' o superior.",
            details={"required_role": minimo.value, "current_role": user.role.value},
        )
