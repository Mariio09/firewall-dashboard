"""CRUD de reglas, reordenacion y validacion de negocio.

Bloque A5. La reordenacion reescribe `position` de 10 en 10 para dejar hueco a
inserciones futuras sin renumerar toda la cadena.

Este modulo NO toca el firewall. Escribe la politica deseada en la base de datos
—que es la fuente de verdad (ADR-0001)— y deja las reglas afectadas en
`sync_state = pending`. Quien reconcilia es `firewall_service`, y quien decide si
eso pasa en el acto (`AUTO_APPLY`) es el router. Separarlo asi es lo que hace que
`AUTO_APPLY=false` sea un flujo de staging tipo Terraform sin reescribir nada.

La conversion `Rule -> RuleSpec` vive aqui, en `spec_de_regla()`, y es la unica:
`firewall_service` la importa de este modulo en vez de tener la suya. Dos
conversiones que se creen iguales y no lo son producirian un drift permanente y
sin causa visible.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.firewall.spec import Chain, IPVersion, RuleSpec, SyncState, Table
from app.models.audit_event import AuditAction
from app.models.rule import POSITION_STEP, Rule
from app.models.user import User
from app.schemas.rule import RuleCreate, RuleUpdate
from app.services import audit_service

__all__ = [
    "create_rule",
    "delete_rule",
    "get_rule",
    "list_rules",
    "reorder_rules",
    "spec_de_regla",
    "toggle_rule",
    "update_rule",
]

#: Prefijo de los `--log-prefix` que genera la aplicacion. Corto a proposito: el
#: limite real de iptables son 29 caracteres y el uuid ya se lleva ocho.
PREFIJO_DE_LOG = "FWD:"


# --------------------------------------------------------------------------- #
# Conversion al tipo frontera
# --------------------------------------------------------------------------- #


def spec_de_regla(rule: Rule) -> RuleSpec:
    """La `RuleSpec` equivalente a una fila de `rules`.

    Construirla valida: si una fila antigua tiene algo que hoy es invalido, salta
    aqui —con un 422 explicando el campo— y no en el argv de iptables.

    El nombre de la regla se pasa como `comment` porque es lo que acaba dentro
    del `-m comment --comment` y lo que se lee en `iptables -L`. Que la etiqueta
    diga "Bloquear escaner del 22" en vez de un uuid suelto es la diferencia
    entre poder auditar la cadena a ojo y no poder.
    """
    return RuleSpec(
        chain=rule.chain,
        action=rule.action,
        protocol=rule.protocol,
        ip_version=rule.ip_version,
        src_ip=rule.src_ip,
        dst_ip=rule.dst_ip,
        src_port=rule.src_port,
        dst_port=rule.dst_port,
        in_interface=rule.in_interface,
        out_interface=rule.out_interface,
        comment=rule.name,
        log_enabled=rule.log_enabled,
        log_prefix=rule.log_prefix,
        rule_uuid=rule.uuid,
    )


def _spec_de_valores(valores: dict[str, Any], *, rule_uuid: str) -> RuleSpec:
    """Igual que `spec_de_regla`, pero desde un diccionario sin fila detras.

    Es lo que permite validar un alta o una modificacion ANTES de tocar la base
    de datos: si la combinacion no es renderizable, no llega a persistirse.
    """
    return RuleSpec(
        chain=valores["chain"],
        action=valores["action"],
        protocol=valores["protocol"],
        ip_version=valores["ip_version"],
        src_ip=valores["src_ip"],
        dst_ip=valores["dst_ip"],
        src_port=valores["src_port"],
        dst_port=valores["dst_port"],
        in_interface=valores["in_interface"],
        out_interface=valores["out_interface"],
        comment=valores["name"],
        log_enabled=valores["log_enabled"],
        log_prefix=valores["log_prefix"],
        rule_uuid=rule_uuid,
    )


def _valores_de_regla(rule: Rule) -> dict[str, Any]:
    """Los campos editables de una fila, como diccionario.

    Es la base sobre la que se aplica un PATCH: se parte del estado actual, se
    superpone lo que llega y se valida el resultado COMPLETO. Validar solo los
    campos que vienen dejaria pasar combinaciones invalidas —cambiar el protocolo
    a `icmp` en una regla que ya tenia puerto— que ningun validador por campo ve.
    """
    return {
        "name": rule.name,
        "description": rule.description,
        "chain": rule.chain,
        "action": rule.action,
        "protocol": rule.protocol,
        "ip_version": rule.ip_version,
        "src_ip": rule.src_ip,
        "dst_ip": rule.dst_ip,
        "src_port": rule.src_port,
        "dst_port": rule.dst_port,
        "in_interface": rule.in_interface,
        "out_interface": rule.out_interface,
        "enabled": rule.enabled,
        "log_enabled": rule.log_enabled,
        "log_prefix": rule.log_prefix,
        "expires_at": rule.expires_at,
    }


def _prefijo_de_log(*, log_enabled: bool, log_prefix: str | None, rule_uuid: str) -> str | None:
    """Rellena el `--log-prefix` que falta, sin pisar el que se haya mandado.

    La columna tiene un CHECK (`log_enabled = 0 OR log_prefix IS NOT NULL`), asi
    que activar el log sin prefijo seria un `IntegrityError` con un mensaje de
    SQLite. Generarlo aqui convierte eso en el caso normal, y el prefijo generado
    lleva el uuid corto: es lo que permite volver de una linea de syslog a la
    fila que la produjo (fase 2).
    """
    if log_enabled and not log_prefix:
        return f"{PREFIJO_DE_LOG}{rule_uuid[:8]}"
    return log_prefix


def _instantanea(rule: Rule) -> dict[str, Any]:
    """Lo que se guarda en `audit_events.payload`: el estado visible de la regla.

    Sin `id` ni `created_by_id`: son internos y no significan nada al leer la
    auditoria seis meses despues. Los campos vacios tampoco se guardan, porque
    una regla usa dos o tres selectores de los diez posibles y el resto solo
    llenaria de `null` la vista de eventos.

    Todo sale como texto o booleano: la columna es JSON, y un `datetime` o un
    `StrEnum` ahi dentro dependeria de como el serializador de turno decida
    tratarlos. La auditoria no puede fallar por eso (invariante 1 de
    `audit_service`).
    """
    valores = _valores_de_regla(rule) | {"position": rule.position}
    instantanea: dict[str, Any] = {}
    for clave, valor in valores.items():
        if valor is None:
            continue
        if clave == "expires_at":
            instantanea[clave] = rule.expires_at.isoformat() if rule.expires_at else None
        elif isinstance(valor, StrEnum):
            instantanea[clave] = valor.value
        else:
            instantanea[clave] = valor
    return instantanea


# --------------------------------------------------------------------------- #
# Lectura
# --------------------------------------------------------------------------- #


def get_rule(session: Session, uuid: str) -> Rule:
    """La regla con ese uuid publico, o `NotFoundError`."""
    regla = session.scalar(select(Rule).where(Rule.uuid == uuid))
    if regla is None:
        raise NotFoundError(
            f"No existe ninguna regla con uuid '{uuid}'.",
            details={"uuid": uuid},
        )
    return regla


def list_rules(
    session: Session,
    *,
    chain: Chain | None = None,
    enabled: bool | None = None,
    q: str | None = None,
    page: int = 1,
    size: int = 50,
) -> tuple[list[Rule], int]:
    """Reglas filtradas y paginadas, mas el total que cumple el filtro.

    El orden es `(chain, position)` y no la fecha de creacion: en iptables el
    orden ES la semantica, asi que la lista tiene que verse como se va a aplicar.

    Se devuelve el total ademas de la pagina porque la tabla del frontend
    necesita saber cuantas paginas hay antes de pintar el paginador.
    """
    consulta = select(Rule)

    if chain is not None:
        consulta = consulta.where(Rule.chain == chain)
    if enabled is not None:
        consulta = consulta.where(Rule.enabled == enabled)
    if q:
        # `%` y `_` son comodines de LIKE: sin escaparlos, buscar "8000_" traeria
        # tambien "80001", y el usuario no tiene forma de saber por que.
        patron = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        consulta = consulta.where(
            or_(Rule.name.ilike(patron, escape="\\"), Rule.description.ilike(patron, escape="\\"))
        )

    total = session.scalar(select(func.count()).select_from(consulta.subquery())) or 0
    filas = session.scalars(
        consulta.order_by(Rule.chain, Rule.position).offset((page - 1) * size).limit(size)
    ).all()
    return list(filas), total


def _siguiente_posicion(session: Session, chain: Chain) -> int:
    """La posicion libre al final de la cadena, en multiplos de `POSITION_STEP`.

    Se calcula desde el maximo y no contando filas: si se borro la regla de en
    medio, contar daria una posicion ya ocupada.
    """
    maximo = session.scalar(select(func.max(Rule.position)).where(Rule.chain == chain))
    return POSITION_STEP if maximo is None else maximo + POSITION_STEP


# --------------------------------------------------------------------------- #
# Escritura
# --------------------------------------------------------------------------- #


def create_rule(
    session: Session,
    datos: RuleCreate,
    *,
    actor: User,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> Rule:
    """Crea una regla al final de su cadena, en estado `pending`.

    El uuid se genera aqui y no se deja al `default` de la columna porque hace
    falta antes de insertar: entra en el `--log-prefix` y en la `RuleSpec` que
    valida el alta.

    Los valores que se guardan son los NORMALIZADOS por la spec, no los que
    llegaron: `1.2.3.4` se guarda como `1.2.3.4/32`. Sin eso, la misma regla
    escrita de dos formas serian dos filas distintas y el drift no cuadraria
    nunca (ADR-0006).
    """
    uuid_nuevo = str(uuid4())
    valores = datos.model_dump()
    valores["ip_version"] = int(IPVersion.V4)
    valores["log_prefix"] = _prefijo_de_log(
        log_enabled=datos.log_enabled, log_prefix=datos.log_prefix, rule_uuid=uuid_nuevo
    )

    spec = _spec_de_valores(valores, rule_uuid=uuid_nuevo)

    regla = Rule(
        uuid=uuid_nuevo,
        name=spec.comment,
        description=datos.description,
        chain=spec.chain,
        table_name=Table.FILTER,
        ip_version=spec.ip_version,
        action=spec.action,
        protocol=spec.protocol,
        src_ip=spec.src_ip,
        dst_ip=spec.dst_ip,
        src_port=spec.src_port,
        dst_port=spec.dst_port,
        in_interface=spec.in_interface,
        out_interface=spec.out_interface,
        position=_siguiente_posicion(session, spec.chain),
        enabled=datos.enabled,
        log_enabled=spec.log_enabled,
        log_prefix=spec.log_prefix,
        expires_at=datos.expires_at,
        sync_state=SyncState.PENDING,
        created_by_id=actor.id,
    )
    session.add(regla)
    session.flush()

    audit_service.record(
        session,
        action=AuditAction.RULE_CREATE,
        user=actor,
        entity_type="rule",
        entity_id=regla.uuid,
        payload=_instantanea(regla),
        client_ip=client_ip,
        request_id=request_id,
    )
    session.commit()
    session.refresh(regla)
    return regla


def update_rule(
    session: Session,
    uuid: str,
    datos: RuleUpdate,
    *,
    actor: User,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> Rule:
    """Modifica una regla. Solo se toca lo que venia en el cuerpo.

    Vuelve a `pending` **solo si el cambio afecta a lo que el firewall hace**:
    la spec de antes y la de despues se comparan por estructura, que es la misma
    comparacion con la que se detecta el drift (ADR-0006). Corregir una falta de
    ortografia en la descripcion no deja la regla marcada como pendiente de
    aplicar, que es ruido en el dashboard y una reaplicacion para nada.
    """
    regla = get_rule(session, uuid)
    cambios = datos.model_dump(exclude_unset=True)
    if not cambios:
        return regla

    antes = _instantanea(regla)
    spec_vieja = spec_de_regla(regla)
    enabled_antes = regla.enabled

    valores = _valores_de_regla(regla) | cambios
    valores["log_prefix"] = _prefijo_de_log(
        log_enabled=valores["log_enabled"], log_prefix=valores["log_prefix"], rule_uuid=regla.uuid
    )
    spec_nueva = _spec_de_valores(valores, rule_uuid=regla.uuid)

    # Cambiar de cadena obliga a buscar sitio en la nueva: la posicion que ocupa
    # aqui puede estar cogida alli, y `UniqueConstraint(chain, position)` lo
    # rechazaria con un IntegrityError en vez de con un mensaje util.
    if spec_nueva.chain is not regla.chain:
        regla.position = _siguiente_posicion(session, spec_nueva.chain)

    regla.name = spec_nueva.comment or regla.name
    regla.description = valores["description"]
    regla.chain = spec_nueva.chain
    regla.action = spec_nueva.action
    regla.protocol = spec_nueva.protocol
    regla.src_ip = spec_nueva.src_ip
    regla.dst_ip = spec_nueva.dst_ip
    regla.src_port = spec_nueva.src_port
    regla.dst_port = spec_nueva.dst_port
    regla.in_interface = spec_nueva.in_interface
    regla.out_interface = spec_nueva.out_interface
    regla.enabled = valores["enabled"]
    regla.log_enabled = spec_nueva.log_enabled
    regla.log_prefix = spec_nueva.log_prefix
    regla.expires_at = valores["expires_at"]

    if spec_nueva != spec_vieja or regla.enabled != enabled_antes:
        regla.sync_state = SyncState.PENDING
        # El error del intento anterior deja de aplicar: describe una regla que
        # ya no es esta. Conservarlo haria que la UI enseñara para siempre un
        # fallo de una version que nadie puede volver a ver.
        regla.last_error = None

    session.flush()
    audit_service.record(
        session,
        action=AuditAction.RULE_UPDATE,
        user=actor,
        entity_type="rule",
        entity_id=regla.uuid,
        payload={"antes": antes, "despues": _instantanea(regla)},
        client_ip=client_ip,
        request_id=request_id,
    )
    session.commit()
    session.refresh(regla)
    return regla


def toggle_rule(
    session: Session,
    uuid: str,
    *,
    actor: User,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> Rule:
    """Activa o desactiva una regla sin borrarla.

    Es su propio endpoint y no un `PATCH {"enabled": false}` porque es la accion
    de un solo clic en la tabla y porque asi queda como `rule.toggle` en la
    auditoria: "alguien desactivo la regla del 22" se distingue de "alguien
    edito la regla del 22", que es justo lo que se quiere saber despues.
    """
    regla = get_rule(session, uuid)
    regla.enabled = not regla.enabled
    regla.sync_state = SyncState.PENDING
    session.flush()

    audit_service.record(
        session,
        action=AuditAction.RULE_TOGGLE,
        user=actor,
        entity_type="rule",
        entity_id=regla.uuid,
        payload={"name": regla.name, "enabled": regla.enabled},
        client_ip=client_ip,
        request_id=request_id,
    )
    session.commit()
    session.refresh(regla)
    return regla


def delete_rule(
    session: Session,
    uuid: str,
    *,
    actor: User,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> Chain:
    """Borra una regla y devuelve la cadena que queda por reconciliar.

    Se devuelve la cadena porque la fila ya no existe y quien llama la necesita
    para reaplicar: sin ese dato habria que adivinarla o reconciliar las tres.

    No se renumeran las posiciones de las demas. Los huecos no molestan —el
    orden es relativo— y renumerar seria un UPDATE masivo, con su riesgo de
    colision, a cambio de nada.
    """
    regla = get_rule(session, uuid)
    cadena = regla.chain
    payload = _instantanea(regla)

    audit_service.record(
        session,
        action=AuditAction.RULE_DELETE,
        user=actor,
        entity_type="rule",
        entity_id=regla.uuid,
        payload=payload,
        client_ip=client_ip,
        request_id=request_id,
    )
    session.delete(regla)
    session.commit()
    return cadena


def reorder_rules(
    session: Session,
    uuids: Sequence[str],
    *,
    actor: User,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> tuple[Chain, list[Rule]]:
    """Reescribe el orden de una cadena entera y devuelve cual era.

    La lista tiene que ser exactamente el conjunto de reglas de una cadena. Un
    reorden parcial dejaria a las que faltan con posiciones antiguas que pueden
    chocar con las nuevas.

    Se hace en DOS FASES porque `UniqueConstraint(chain, position)` se comprueba
    en cada UPDATE, no al final de la transaccion: reasignar 10,20,30 sobre unas
    filas que ya ocupan 10,20,30 hace que el primer UPDATE choque con una fila
    que aun no se ha movido. La primera fase las manda a un rango por encima del
    maximo actual, donde no hay nadie; la segunda las trae a su sitio definitivo.
    """
    if len(set(uuids)) != len(uuids):
        raise ValidationError(
            "La lista de reorden tiene uuids repetidos.",
            details={"campo": "uuids"},
        )

    reglas = {
        regla.uuid: regla for regla in session.scalars(select(Rule).where(Rule.uuid.in_(uuids)))
    }
    desconocidos = [uuid for uuid in uuids if uuid not in reglas]
    if desconocidos:
        raise NotFoundError(
            "Algunos uuids de la lista no corresponden a ninguna regla.",
            details={"uuids": desconocidos},
        )

    cadenas = {regla.chain for regla in reglas.values()}
    if len(cadenas) > 1:
        raise ValidationError(
            "Todas las reglas de un reorden tienen que ser de la misma cadena: el "
            "orden solo significa algo dentro de una cadena.",
            details={"chains": sorted(cadena.value for cadena in cadenas)},
        )
    cadena = cadenas.pop()

    de_la_cadena = set(session.scalars(select(Rule.uuid).where(Rule.chain == cadena)))
    if de_la_cadena != set(uuids):
        raise ConflictError(
            f"El reorden tiene que incluir las {len(de_la_cadena)} reglas de la cadena "
            f"{cadena.value}, y ha llegado con {len(uuids)}.",
            details={
                "chain": cadena.value,
                "faltan": sorted(de_la_cadena - set(uuids)),
            },
        )

    orden_anterior = [
        regla.uuid for regla in sorted(reglas.values(), key=lambda regla: regla.position)
    ]
    if orden_anterior == list(uuids):
        return cadena, [reglas[uuid] for uuid in uuids]

    # Fase 1: a un rango vacio, por encima de todo lo que hay.
    base = max(regla.position for regla in reglas.values()) + POSITION_STEP
    for indice, uuid in enumerate(uuids):
        reglas[uuid].position = base + indice
    session.flush()

    # Fase 2: al sitio definitivo, de 10 en 10.
    for indice, uuid in enumerate(uuids):
        regla = reglas[uuid]
        regla.position = (indice + 1) * POSITION_STEP
        regla.sync_state = SyncState.PENDING
    session.flush()

    audit_service.record(
        session,
        action=AuditAction.RULE_REORDER,
        user=actor,
        entity_type="chain",
        entity_id=cadena.value,
        payload={"antes": orden_anterior, "despues": list(uuids)},
        client_ip=client_ip,
        request_id=request_id,
    )
    session.commit()
    return cadena, [reglas[uuid] for uuid in uuids]
