"""Schemas de autenticacion: LoginRequest, TokenPair, UserRead.

Bloque A4. Estos modelos son el contrato con el frontend; los de SQLAlchemy son
como se guardan las cosas. Que sean dos capas distintas es lo que impide que
`hashed_password` aparezca en una respuesta por haber añadido una columna.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.user import Role

__all__ = ["LoginRequest", "RefreshRequest", "TokenPair", "UserRead"]


class LoginRequest(BaseModel):
    """Credenciales de entrada.

    Los limites son de cordura, no de politica de contraseñas: rechazar aqui una
    contraseña de 5 caracteres solo le diria al atacante que no lo intente. La
    politica, cuando la haya, va en la creacion del usuario.
    """

    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=1024)

    model_config = ConfigDict(
        # `***` es el marcador del ejemplo que sale en /docs, no una credencial:
        # bandit marca cualquier literal junto a una clave llamada "password", y
        # aqui es justo lo contrario de un secreto filtrado. El `nosec` va EN la
        # linea marcada; puesto encima no silencia nada.
        json_schema_extra={"example": {"username": "admin", "password": "***"}}  # nosec B105
    )


class RefreshRequest(BaseModel):
    """El refresh viaja en el cuerpo, no en la cabecera `Authorization`.

    Asi el interceptor del frontend puede tener una regla unica —"pon el access
    token en `Authorization`"— sin excepciones para un endpoint.
    """

    refresh_token: str = Field(min_length=1)


class TokenPair(BaseModel):
    """Respuesta de `/login` y `/refresh`.

    `token_type` es literalmente `"bearer"` porque lo pide el RFC 6750 y porque
    los clientes OAuth2 genericos lo esperan. `expires_in` va en segundos, como
    manda el mismo RFC, para que el frontend pueda programar el refresco sin
    tener que decodificar el token.
    """

    access_token: str
    refresh_token: str
    # `noqa`: el linter ve un campo cuyo nombre lleva "token" con un literal
    # dentro y sospecha una credencial en el codigo. Aqui el literal es el tipo
    # de esquema que fija el RFC 6750, no un secreto.
    token_type: str = "bearer"  # noqa: S105
    expires_in: int = Field(description="Validez del access token, en segundos.")


class UserRead(BaseModel):
    """El usuario tal y como lo ve la API. Sin `hashed_password`, obviamente."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None = None
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None
