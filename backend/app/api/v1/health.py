"""Endpoints de salud: /health (liveness, sin auth) y /ready (DB + firewall).

Bloque A1."""

from __future__ import annotations

from fastapi import APIRouter, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import CurrentSettings, DbSession
from app.core.logging import get_logger
from app.schemas.common import HealthResponse, ReadinessResponse

__all__ = ["router"]

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
)
def health() -> HealthResponse:
    """¿Esta vivo el proceso?

    No toca la base de datos ni pide autenticacion, a proposito: si dependiera
    de algo mas, una base de datos caida provocaria reinicios en bucle que no
    arreglarian la base de datos.
    """
    return HealthResponse(status="ok")


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    responses={503: {"description": "Alguna dependencia no responde."}},
)
def ready(
    session: DbSession,
    settings: CurrentSettings,
    response: Response,
) -> ReadinessResponse:
    """¿Puede la aplicacion atender trabajo real?

    Devuelve 503 si alguna comprobacion falla, para que el resultado sea util a
    un supervisor sin tener que leer el cuerpo de la respuesta.
    """
    checks: dict[str, str] = {}

    try:
        session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except SQLAlchemyError as exc:
        # El mensaje real de la excepcion puede llevar la ruta del fichero de la
        # base de datos; al cliente le basta con "error".
        logger.error("readiness_db_ko", exc_info=exc)
        checks["database"] = "error"

    # El firewall todavia no se sondea: `FakeFirewallBackend` no tiene nada que
    # sondear y `IptablesBackend` no existe hasta el bloque B.
    # TODO(C2): comprobar aqui `ensure_scaffold` y la existencia de las cadenas
    # FWDASH_*, que es lo que de verdad indica que la aplicacion puede aplicar.
    checks["firewall"] = "not_checked"

    degradado = any(estado == "error" for estado in checks.values())
    if degradado:
        response.status_code = 503

    return ReadinessResponse(
        status="degraded" if degradado else "ready",
        checks=checks,
        firewall_backend=settings.firewall_backend,
    )
