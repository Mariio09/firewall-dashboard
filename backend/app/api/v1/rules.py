"""Endpoints CRUD de reglas + toggle + reorder.

Bloque A5. Como los de auth, estos handlers son finos a proposito: validan la
entrada con un schema, llaman a `rule_service` y traducen el resultado. Toda la
logica esta en el servicio, que se puede probar sin levantar HTTP.

Lo que estos endpoints escriben es la POLITICA DESEADA, no el firewall: cada
mutacion deja las reglas afectadas en `sync_state = pending`. Aplicarlas es
`POST /firewall/apply`, y con `AUTO_APPLY=true` (por defecto) ocurre en la misma
peticion. Esa separacion es lo que hace que `AUTO_APPLY=false` de un flujo de
staging tipo Terraform sin reescribir una linea.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.deps import (
    ClientIp,
    CurrentSettings,
    DbSession,
    Firewall,
    RequestId,
    RequireOperator,
    RequireViewer,
)
from app.schemas.common import ErrorResponse, Page
from app.schemas.rule import (
    Chain,
    ReorderRequest,
    RuleCreate,
    RuleListItem,
    RuleRead,
    RuleUpdate,
)
from app.services import firewall_service, rule_service

__all__ = ["router"]

router = APIRouter(prefix="/rules", tags=["rules"])

#: Declarados una vez para que la documentacion no se separe de la realidad.
RESPUESTAS_PROTEGIDAS: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse, "description": "Falta el token o no es valido."},
    403: {"model": ErrorResponse, "description": "El rol no alcanza."},
}
RESPUESTAS_404: dict[int | str, dict[str, object]] = {
    404: {"model": ErrorResponse, "description": "No existe una regla con ese uuid."}
}


@router.get(
    "",
    response_model=Page[RuleListItem],
    responses=RESPUESTAS_PROTEGIDAS,
    summary="Listar reglas",
)
def listar(
    session: DbSession,
    usuario: RequireViewer,
    chain: Annotated[Chain | None, Query(description="Filtra por cadena.")] = None,
    enabled: Annotated[bool | None, Query(description="Solo activas o solo inactivas.")] = None,
    q: Annotated[
        str | None, Query(max_length=100, description="Busca en nombre y descripcion.")
    ] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=500)] = 50,
) -> Page[RuleListItem]:
    """Las reglas, ordenadas como se aplican: por cadena y posicion.

    Leer no exige mas que estar autenticado. Un `viewer` es precisamente el rol
    de quien tiene que poder auditar la politica sin poder cambiarla.
    """
    del usuario  # la dependencia esta por el permiso, no por el dato
    filas, total = rule_service.list_rules(
        session, chain=chain, enabled=enabled, q=q, page=page, size=size
    )
    return Page[RuleListItem](
        items=[RuleListItem.model_validate(fila) for fila in filas],
        total=total,
        page=page,
        size=size,
    )


@router.post(
    "",
    response_model=RuleRead,
    status_code=status.HTTP_201_CREATED,
    responses=RESPUESTAS_PROTEGIDAS,
    summary="Crear una regla",
)
def crear(
    datos: RuleCreate,
    session: DbSession,
    firewall: Firewall,
    settings: CurrentSettings,
    usuario: RequireOperator,
    client_ip: ClientIp,
    request_id: RequestId,
) -> RuleRead:
    """Crea una regla al final de su cadena y, con `AUTO_APPLY`, la aplica.

    La respuesta devuelve los valores NORMALIZADOS, que pueden no ser los que se
    mandaron: `1.2.3.4` vuelve como `1.2.3.4/32`. Es deliberado —el frontend
    tiene que enseñar lo que se guardo, no lo que se escribio— y es lo que hace
    que la deteccion de drift pueda comparar por estructura (ADR-0006).

    El `sync_state` de la respuesta dice como acabo: `applied` si se aplico,
    `pending` con `AUTO_APPLY=false`, `failed` si el firewall no pudo. Es 201 en
    los tres casos, porque en los tres la regla existe.
    """
    regla = rule_service.create_rule(
        session, datos, actor=usuario, client_ip=client_ip, request_id=request_id
    )
    firewall_service.reconciliar_si_auto(
        session,
        firewall,
        regla.chain,
        settings=settings,
        actor=usuario,
        client_ip=client_ip,
        request_id=request_id,
    )
    return RuleRead.model_validate(regla)


@router.post(
    "/reorder",
    response_model=list[RuleListItem],
    responses=RESPUESTAS_PROTEGIDAS | RESPUESTAS_404,
    summary="Reordenar una cadena",
)
def reordenar(
    datos: ReorderRequest,
    session: DbSession,
    firewall: Firewall,
    settings: CurrentSettings,
    usuario: RequireOperator,
    client_ip: ClientIp,
    request_id: RequestId,
) -> list[RuleListItem]:
    """Reescribe el orden de una cadena entera.

    Va declarado ANTES que `/{uuid}` no por casualidad: FastAPI resuelve las
    rutas en orden de registro, y con `/{uuid}` delante, `/rules/reorder`
    entraria por ahi con el uuid literal `"reorder"`.

    El cuerpo tiene que traer todas las reglas de la cadena. Si falta alguna,
    409 con la lista de las que faltan: es un error del cliente y se puede
    arreglar sin adivinar.
    """
    cadena, reglas = rule_service.reorder_rules(
        session, datos.uuids, actor=usuario, client_ip=client_ip, request_id=request_id
    )
    firewall_service.reconciliar_si_auto(
        session,
        firewall,
        cadena,
        settings=settings,
        actor=usuario,
        client_ip=client_ip,
        request_id=request_id,
    )
    return [RuleListItem.model_validate(regla) for regla in reglas]


@router.get(
    "/{uuid}",
    response_model=RuleRead,
    responses=RESPUESTAS_PROTEGIDAS | RESPUESTAS_404,
    summary="Ver una regla",
)
def ver(uuid: str, session: DbSession, usuario: RequireViewer) -> RuleRead:
    """Una regla completa, con su estado de sincronizacion y su ultimo error."""
    del usuario
    return RuleRead.model_validate(rule_service.get_rule(session, uuid))


@router.patch(
    "/{uuid}",
    response_model=RuleRead,
    responses=RESPUESTAS_PROTEGIDAS | RESPUESTAS_404,
    summary="Modificar una regla",
)
def modificar(
    uuid: str,
    datos: RuleUpdate,
    session: DbSession,
    firewall: Firewall,
    settings: CurrentSettings,
    usuario: RequireOperator,
    client_ip: ClientIp,
    request_id: RequestId,
) -> RuleRead:
    """Modificacion parcial: solo se toca lo que venga en el cuerpo.

    `PATCH` y no `PUT` porque el cliente no tiene por que conocer la regla
    entera para cambiarle el puerto, y porque mandarla entera abriria la puerta
    a pisar sin querer un campo que otro acaba de cambiar.
    """
    regla = rule_service.update_rule(
        session, uuid, datos, actor=usuario, client_ip=client_ip, request_id=request_id
    )
    firewall_service.reconciliar_si_auto(
        session,
        firewall,
        regla.chain,
        settings=settings,
        actor=usuario,
        client_ip=client_ip,
        request_id=request_id,
    )
    return RuleRead.model_validate(regla)


@router.post(
    "/{uuid}/toggle",
    response_model=RuleRead,
    responses=RESPUESTAS_PROTEGIDAS | RESPUESTAS_404,
    summary="Activar o desactivar una regla",
)
def alternar(
    uuid: str,
    session: DbSession,
    firewall: Firewall,
    settings: CurrentSettings,
    usuario: RequireOperator,
    client_ip: ClientIp,
    request_id: RequestId,
) -> RuleRead:
    """Invierte `enabled`. La regla sigue existiendo; el renderer la omite.

    Desactivar en vez de borrar es lo que permite probar si una regla es la que
    esta rompiendo algo y devolverla en un clic, con su descripcion intacta.
    """
    regla = rule_service.toggle_rule(
        session, uuid, actor=usuario, client_ip=client_ip, request_id=request_id
    )
    firewall_service.reconciliar_si_auto(
        session,
        firewall,
        regla.chain,
        settings=settings,
        actor=usuario,
        client_ip=client_ip,
        request_id=request_id,
    )
    return RuleRead.model_validate(regla)


@router.delete(
    "/{uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=RESPUESTAS_PROTEGIDAS | RESPUESTAS_404,
    summary="Borrar una regla",
)
def borrar(
    uuid: str,
    session: DbSession,
    firewall: Firewall,
    settings: CurrentSettings,
    usuario: RequireOperator,
    client_ip: ClientIp,
    request_id: RequestId,
) -> None:
    """Borra la regla de la base de datos y reconstruye su cadena.

    Con `AUTO_APPLY=false` la regla sigue viva en iptables hasta la siguiente
    reconciliacion, y eso no es un fallo: la fuente de verdad es la DB y el
    firewall la refleja, no al reves (ADR-0001). El `sync_state` de la cadena es
    lo que hace visible esa distancia.

    Por eso `delete_rule` devuelve la cadena: la fila ya no existe y sin ese dato
    habria que adivinarla o reconstruir las tres para nada.
    """
    cadena = rule_service.delete_rule(
        session, uuid, actor=usuario, client_ip=client_ip, request_id=request_id
    )
    # `forzar`: la fila que pedia el cambio ya no existe, asi que no queda nada
    # marcado como pendiente. Sin esto, borrar una regla no la quitaria de la
    # cadena hasta el siguiente apply.
    firewall_service.reconciliar_si_auto(
        session,
        firewall,
        cadena,
        settings=settings,
        forzar=True,
        actor=usuario,
        client_ip=client_ip,
        request_id=request_id,
    )
