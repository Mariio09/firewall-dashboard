"""Primitivas de seguridad: hash de passwords (Argon2) y encode/decode de JWT.

Bloque A4. Este modulo no conoce la base de datos ni FastAPI: solo cripto.

Que este archivo no importe nada de `app.models`, `app.db` ni `fastapi` es
deliberado y comprobable: convierte toda la parte delicada de la autenticacion
en funciones puras que se pueden testear sin levantar nada.
"""

from __future__ import annotations

import contextlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import Settings
from app.core.exceptions import AuthError

__all__ = [
    "TokenPayload",
    "TokenType",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "hash_password",
    "needs_rehash",
    "verify_password",
    "waste_time_like_a_verification",
]


class TokenType(StrEnum):
    """Para que un refresh no valga como access.

    Sin este claim, el token de refresco —que dura siete dias— serviria para
    llamar a cualquier endpoint, y el `ACCESS_TOKEN_EXPIRE_MINUTES=30` seria
    decorativo. La comprobacion se hace SIEMPRE al decodificar, no en el
    handler: olvidarla en un endpoint nuevo no debe poder pasar.
    """

    ACCESS = "access"
    REFRESH = "refresh"


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #

#: Un unico hasher para todo el proceso: construirlo es barato, pero tener uno
#: solo garantiza que todos los hashes salen con los mismos parametros.
#:
#: Se usan los valores por defecto de `argon2-cffi` (Argon2id, 3 pasadas,
#: 64 MiB, 4 hilos), que siguen la recomendacion de la RFC 9106 para el caso
#: "sin restricciones de memoria". Subirlos aqui no rompe nada: `needs_rehash`
#: detecta los hashes viejos y el login los actualiza.
_hasher = PasswordHasher()

#: Hash de una contraseña que nadie usa. Sirve para gastar el mismo tiempo
#: cuando el usuario no existe (ver `waste_time_like_a_verification`).
_HASH_SENUELO = _hasher.hash("una contraseña que no es de nadie")


def hash_password(password: str) -> str:
    """Devuelve el hash Argon2id de una contraseña.

    El salt lo genera `argon2-cffi` y viaja dentro de la cadena resultante,
    junto con los parametros: por eso `verify_password` no necesita saber con
    que coste se hasheo, y por eso subir el coste no invalida los hashes viejos.
    """
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """¿Corresponde la contraseña a este hash?

    Devuelve `False` en vez de propagar: para quien llama, "no coincide" y "el
    hash de la base de datos esta corrupto" son el mismo caso —no dejar entrar—
    y distinguirlos en la respuesta HTTP seria decirle a un atacante que ese
    usuario existe.
    """
    try:
        return _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """¿Se hasheo con parametros mas debiles que los actuales?

    Se comprueba en el login, que es el unico momento en el que existe la
    contraseña en claro y por tanto el unico en el que se puede rehashear.
    """
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        # Un hash ilegible es peor que uno anticuado: reescribirlo en el
        # proximo login correcto es exactamente lo que queremos.
        return True


def waste_time_like_a_verification() -> None:
    """Verifica un hash señuelo para que el usuario inexistente cueste lo mismo.

    Sin esto, un login contra un usuario que no existe responde en microsegundos
    y uno con la contraseña equivocada tarda lo que tarda Argon2 (~50 ms a
    proposito). Esa diferencia es medible desde fuera y convierte el endpoint de
    login en un enumerador de usuarios.
    """
    with contextlib.suppress(VerificationError, InvalidHashError):
        _hasher.verify(_HASH_SENUELO, "cualquier cosa")


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Contenido util de un token ya validado.

    Se devuelve un objeto tipado y no el diccionario crudo de `jwt.decode` para
    que el resto del codigo no tenga que acordarse de que `sub` es texto aunque
    el id sea un entero (lo exige la RFC 7519).
    """

    user_id: int
    username: str
    role: str
    token_type: TokenType
    jti: str
    expires_at: datetime


def _crear_token(
    *,
    user_id: int,
    username: str,
    role: str,
    token_type: TokenType,
    expires_delta: timedelta,
    settings: Settings,
) -> str:
    """Firma un token. Es el unico sitio del proyecto que llama a `jwt.encode`."""
    ahora = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": token_type.value,
        "jti": uuid.uuid4().hex,
        "iat": ahora,
        "exp": ahora + expires_delta,
    }
    return jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def create_access_token(*, user_id: int, username: str, role: str, settings: Settings) -> str:
    """Token de acceso, corto. Es el que viaja en cada peticion."""
    return _crear_token(
        user_id=user_id,
        username=username,
        role=role,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
        settings=settings,
    )


def create_refresh_token(*, user_id: int, username: str, role: str, settings: Settings) -> str:
    """Token de refresco, largo. Solo sirve para pedir un access nuevo.

    Es deliberadamente stateless en el MVP: no hay tabla de tokens, asi que
    **no se puede revocar** antes de que caduque. La consecuencia esta asumida y
    documentada (ADR-0008); la tabla `refresh_tokens` con rotacion y revocacion
    es el siguiente paso natural, y el `jti` ya viaja dentro para no tener que
    cambiar el formato del token cuando llegue.
    """
    return _crear_token(
        user_id=user_id,
        username=username,
        role=role,
        token_type=TokenType.REFRESH,
        expires_delta=timedelta(days=settings.refresh_token_expire_days),
        settings=settings,
    )


def decode_token(
    token: str, *, settings: Settings, expected_type: TokenType = TokenType.ACCESS
) -> TokenPayload:
    """Valida firma, caducidad y tipo, y devuelve el contenido.

    Lanza `AuthError` ante cualquier problema, con un mensaje que distingue el
    token caducado del invalido: esa diferencia si es util al cliente (uno se
    arregla refrescando, el otro volviendo a hacer login) y no le dice nada a
    un atacante que no sepa ya.

    `algorithms` va explicito y en singular por el ataque clasico de confusion
    de algoritmo: si se aceptara lo que diga la cabecera del propio token, un
    `alg: none` —o un HS256 firmado con la clave publica de un RS256— pasaria
    la validacion.
    """
    try:
        crudo = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("El token ha caducado.", code="token_expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("El token no es valido.", code="token_invalid") from exc

    tipo = crudo.get("type")
    if tipo != expected_type.value:
        raise AuthError(
            f"Se esperaba un token de tipo '{expected_type.value}'.",
            code="token_wrong_type",
        )

    try:
        user_id = int(crudo["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthError("El token no identifica a ningun usuario.", code="token_invalid") from exc

    return TokenPayload(
        user_id=user_id,
        username=str(crudo.get("username", "")),
        role=str(crudo.get("role", "")),
        token_type=TokenType(tipo),
        jti=str(crudo.get("jti", "")),
        expires_at=datetime.fromtimestamp(crudo["exp"], tz=UTC),
    )
