"""Endpoints /firewall: apply, preview (dry-run), status.

Bloque A5. Los tres viven en `firewall_service`; aqui solo se traduce a HTTP y se
exige el rol.

`preview` no es un modo escondido ni un endpoint que pueda divergir del apply: es
la misma reconciliacion con `dry_run=True`, y esta en el contrato porque ver el
argv exacto antes de ejecutarlo es la mitigacion nº2 del problema del auto-bloqueo
(docs/ARCHITECTURE.md §0). Contra el fake ya es demostrable en el host, sin VM.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import (
    ClientIp,
    CurrentSettings,
    DbSession,
    Firewall,
    RequestId,
    RequireOperator,
    RequireViewer,
)
from app.schemas.common import ErrorResponse
from app.schemas.firewall import ApplyResponse, FirewallStatus
from app.services import firewall_service

__all__ = ["router"]

router = APIRouter(prefix="/firewall", tags=["firewall"])

RESPUESTAS: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse, "description": "Falta el token o no es valido."},
    403: {"model": ErrorResponse, "description": "El rol no alcanza."},
    502: {"model": ErrorResponse, "description": "El firewall no ha podido cumplir la orden."},
}


@router.post(
    "/apply",
    response_model=ApplyResponse,
    responses=RESPUESTAS,
    summary="Reconciliar la politica contra el firewall",
)
def aplicar(
    session: DbSession,
    firewall: Firewall,
    usuario: RequireOperator,
    client_ip: ClientIp,
    request_id: RequestId,
) -> ApplyResponse:
    """Reconstruye las tres cadenas gestionadas desde la base de datos.

    Una sola operacion, tanto si has añadido una regla como si has borrado diez:
    se vacia la cadena y se reconstruye entera, en orden (ADR-0002). De ahi que
    sea idempotente y que no existan `add_rule` ni `delete_rule`.

    Aqui SI se propaga el fallo del firewall como 502: quien llama a este
    endpoint esta pidiendo explicitamente que se aplique, y decirle que ha ido
    bien cuando no ha ido bien seria mentirle. Es la diferencia con el
    auto-apply, donde el 502 escondería que la regla si se creo.
    """
    return firewall_service.apply_chains(
        session,
        firewall,
        actor=usuario,
        client_ip=client_ip,
        request_id=request_id,
    )


@router.get(
    "/preview",
    response_model=ApplyResponse,
    responses=RESPUESTAS,
    summary="Ver los comandos sin ejecutarlos",
)
def previsualizar(
    session: DbSession,
    firewall: Firewall,
    usuario: RequireOperator,
) -> ApplyResponse:
    """Los comandos exactos que ejecutaria `apply`, sin ejecutar ninguno.

    Pide rol `operator` aunque solo lea. No es por el contenido de las reglas
    —un `viewer` ya puede listarlas— sino porque la salida incluye las reglas
    guardian, y con ellas el puerto y el rango desde los que se administra la
    maquina. Eso es topologia de la red de gestion, y quien no puede aplicar
    tampoco necesita conocerla. Relajarlo a `viewer` es cambiar una palabra.
    """
    del usuario
    return firewall_service.apply_chains(session, firewall, dry_run=True)


@router.get(
    "/status",
    response_model=FirewallStatus,
    responses=RESPUESTAS,
    summary="Estado del firewall: drift, contadores y pendientes",
)
def estado(
    session: DbSession,
    firewall: Firewall,
    settings: CurrentSettings,
    usuario: RequireViewer,
) -> FirewallStatus:
    """Compara `iptables -S FWDASH_*` con la base de datos y devuelve la foto.

    Es lo que alimenta el badge de estado y el banner de drift. Un dashboard que
    solo enseñe la tabla `rules` esta enseñando una intencion; este endpoint es
    el que la convierte en un estado.

    De paso refresca los contadores de paquetes y bytes de cada regla: es la
    misma lectura del sistema, y separarla en otro endpoint solo daria una cosa
    mas que el frontend tendria que acordarse de llamar.
    """
    del usuario
    return firewall_service.build_status(session, firewall, settings=settings)
