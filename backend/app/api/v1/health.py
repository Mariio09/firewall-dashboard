"""Endpoints de salud: /health (liveness, sin auth) y /ready (DB + firewall).

Bloque A1. En C2 `/ready` deja de mentir: sondea tambien el firewall. Era deuda
anotada desde B3 (docs/adr/0015-la-aplicacion-arranca-aunque-el-firewall-no-responda.md),
porque "listo" no puede significar solo "la base de datos responde" en una
aplicacion cuyo trabajo es escribir en iptables."""

from __future__ import annotations

from fastapi import APIRouter, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import CurrentSettings, DbSession, FirewallMontado
from app.core.logging import get_logger
from app.schemas.common import HealthResponse, ReadinessResponse
from app.services import firewall_service

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
    firewall: FirewallMontado,
    response: Response,
) -> ReadinessResponse:
    """¿Puede la aplicacion atender trabajo real?

    Devuelve 503 si alguna comprobacion falla, para que el resultado sea util a
    un supervisor sin tener que leer el cuerpo de la respuesta.

    `firewall` llega por `get_firewall_montado`, que NO construye el backend si
    falta. Una sonda que reparase lo que mide siempre diria que si.
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

    # El firewall, sondeado de verdad desde C2. Tres estados y no dos, porque el
    # motivo cambia lo que hay que hacer: `not_mounted` es que el arranque no
    # pudo construirlo (ADR-0015, mira el log de arranque) y `error` es que esta
    # construido pero sus cadenas no se leen (alguien las borro, o iptables ya no
    # responde). Los dos degradan, y ese es el punto: hasta C2 esto devolvia
    # `not_checked` y un 200, o sea "listo" sobre una aplicacion incapaz de
    # aplicar una sola regla.
    if firewall is None:
        checks["firewall"] = "not_mounted"
    elif firewall_service.hay_scaffold(firewall):
        checks["firewall"] = "ok"
    else:
        checks["firewall"] = "error"

    degradado = any(estado != "ok" for estado in checks.values())
    if degradado:
        response.status_code = 503

    return ReadinessResponse(
        status="degraded" if degradado else "ready",
        checks=checks,
        firewall_backend=settings.firewall_backend,
    )
