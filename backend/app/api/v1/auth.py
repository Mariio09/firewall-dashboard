"""Endpoints de autenticacion: login, refresh, me.

Bloque A4. Estos handlers son deliberadamente finos: validan la entrada con un
schema, llaman a `auth_service` y traducen el resultado. Toda la logica —y todas
las decisiones de seguridad— estan en el servicio, que se puede probar sin HTTP.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from app.api.deps import ClientIp, CurrentSettings, CurrentUser, DbSession, RequestId
from app.schemas.auth import LoginRequest, RefreshRequest, TokenPair, UserRead
from app.schemas.common import ErrorResponse
from app.services import auth_service

__all__ = ["router"]

router = APIRouter(prefix="/auth", tags=["auth"])

#: Los tres endpoints responden 401 de la misma forma; declararlo una vez evita
#: que la documentacion y la realidad se separen.
RESPUESTAS_401: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse, "description": "Credenciales o token invalidos."}
}


@router.post(
    "/login",
    response_model=TokenPair,
    responses=RESPUESTAS_401,
    summary="Obtener un par de tokens",
)
def login(
    datos: LoginRequest,
    session: DbSession,
    settings: CurrentSettings,
    client_ip: ClientIp,
    request_id: RequestId,
) -> TokenPair:
    """Comprueba usuario y contraseña y devuelve access + refresh.

    Responde lo mismo —401 y "usuario o contraseña incorrectos"— tanto si el
    usuario no existe como si la contraseña falla o la cuenta esta desactivada.
    El motivo real queda en `audit_events`, que es donde sirve para algo.
    """
    _, tokens = auth_service.login(
        session,
        username=datos.username,
        password=datos.password,
        settings=settings,
        client_ip=client_ip,
        request_id=request_id,
    )
    return TokenPair(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
    )


@router.post(
    "/refresh",
    response_model=TokenPair,
    responses=RESPUESTAS_401,
    summary="Renovar el access token",
)
def refresh(
    datos: RefreshRequest,
    session: DbSession,
    settings: CurrentSettings,
) -> TokenPair:
    """Cambia un refresh token valido por un par nuevo.

    No consume el token entregado: en el MVP el refresco es stateless y no hay
    donde marcarlo como usado (ADR-0008). Lo que si se comprueba es que la
    cuenta siga existiendo y activa.
    """
    _, tokens = auth_service.refresh(session, refresh_token=datos.refresh_token, settings=settings)
    return TokenPair(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
    )


@router.get(
    "/me",
    response_model=UserRead,
    responses=RESPUESTAS_401,
    status_code=status.HTTP_200_OK,
    summary="Quien soy",
)
def me(usuario: CurrentUser) -> UserRead:
    """El usuario del token actual.

    Es lo que el frontend llama al arrancar para saber si la sesion guardada
    sigue viva y que puede enseñar segun el rol.
    """
    return UserRead.model_validate(usuario)
