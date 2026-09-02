"""Reconciliacion DB -> iptables, deteccion de drift y dry-run.

Bloque A5. El corazon del diseño (ADR-0002): 'aplicar' significa siempre vaciar
la cadena gestionada y reconstruirla entera desde la DB, en orden. Idempotente.
Se itera sobre las tres cadenas (INPUT / OUTPUT / FORWARD) de forma independiente.

Las REGLAS GUARDIAN las emite el renderer en cabecera de cada cadena; no estan en
la DB y no se pueden desactivar por API. Aqui aparecen solo al leer: el parser las
marca como `is_guardian` para que la deteccion de drift no las busque en `rules` y
las de por sobrantes. Ver docs/ARCHITECTURE.md §0.

Una sola funcion escribe en el firewall, `apply_chains`, y tanto el apply como el
preview pasan por ella: el preview es la misma llamada con `dry_run=True`. Si
fueran dos caminos podrian divergir, y entonces el preview dejaria de servir para
lo unico para lo que existe — ver antes de ejecutar (mitigacion nº2 del problema
del auto-bloqueo).
"""

from __future__ import annotations

import shlex
from collections import Counter
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import FirewallError
from app.core.logging import get_logger
from app.db.base import utcnow
from app.firewall.base import FirewallBackend
from app.firewall.spec import ApplyResult, Chain, RuleSpec, SyncState
from app.models.audit_event import AuditAction, AuditResult
from app.models.rule import Rule
from app.models.user import User
from app.schemas.firewall import ApplyResponse, ChainApply, ChainDrift, FirewallStatus
from app.services import audit_service, rule_service

__all__ = [
    "apply_chains",
    "build_status",
    "reconciliar_si_auto",
    "specs_de_cadena",
]

logger = get_logger(__name__)

#: Longitud maxima de `rules.last_error`. El mensaje que llega aqui ya viene
#: saneado por el backend —el stderr crudo se queda en el log, porque puede
#: llevar rutas y topologia de red—, pero un error largo en una columna que se
#: pinta en una tabla no ayuda a nadie.
MAX_LAST_ERROR = 500


# --------------------------------------------------------------------------- #
# Politica deseada
# --------------------------------------------------------------------------- #


def _reglas_de_cadena(session: Session, chain: Chain) -> list[Rule]:
    """Todas las reglas de una cadena, en el orden en el que se aplicarian."""
    return list(session.scalars(select(Rule).where(Rule.chain == chain).order_by(Rule.position)))


def specs_de_cadena(session: Session, chain: Chain) -> list[RuleSpec]:
    """Lo que la cadena DEBERIA contener: las reglas activas, en orden.

    Las desactivadas se omiten en vez de borrarse. Esa es toda la implementacion
    de `enabled`: la fila sigue en la tabla con su descripcion intacta, y el
    renderer no la ve.

    TODO(fase 4): `expires_at` todavia no se mira. Una regla caducada se sigue
    aplicando hasta que alguien la borra. Filtrarla aqui es una linea, pero deja
    la fila diciendo `applied` mientras no esta en la cadena, asi que el auto-ban
    tendra que apagarlas de verdad (`enabled = false`) y no solo ignorarlas.
    """
    return [
        rule_service.spec_de_regla(regla)
        for regla in _reglas_de_cadena(session, chain)
        if regla.enabled
    ]


# --------------------------------------------------------------------------- #
# Escritura
# --------------------------------------------------------------------------- #


def _marcar_aplicadas(reglas: Sequence[Rule]) -> None:
    """Toda la cadena pasa a `applied`: la DB y el firewall vuelven a coincidir.

    Tambien las desactivadas, y no es un descuido. `applied` significa "la DB y
    iptables dicen lo mismo", y de una regla desactivada las dos dicen lo mismo:
    que no esta. Lo que no se les toca es `applied_at`, que es la fecha de la
    ultima vez que la regla estuvo de verdad en la cadena.
    """
    ahora = utcnow()
    for regla in reglas:
        regla.sync_state = SyncState.APPLIED
        regla.last_error = None
        if regla.enabled:
            regla.applied_at = ahora


def _marcar_fallidas(reglas: Sequence[Rule], exc: FirewallError) -> None:
    """Solo las activas: las desactivadas no iban a ninguna parte.

    La reconstruccion es atomica desde el punto de vista del modelo —o queda la
    cadena entera o no queda—, asi que el fallo es de todas a la vez y no de la
    regla que lo provoco. Cual fue exactamente se averigua con el preview.
    """
    mensaje = exc.message[:MAX_LAST_ERROR]
    for regla in reglas:
        if regla.enabled:
            regla.sync_state = SyncState.FAILED
            regla.last_error = mensaje


def apply_chains(
    session: Session,
    backend: FirewallBackend,
    *,
    chains: Sequence[Chain] | None = None,
    dry_run: bool = False,
    actor: User | None = None,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> ApplyResponse:
    """Reconstruye las cadenas indicadas (por defecto las tres) desde la DB.

    Con `dry_run=True` no se toca ni el firewall ni la base de datos: se
    devuelven los comandos que se ejecutarian. Es el mismo recorrido, la misma
    validacion y el mismo renderer, que es justo lo que hace fiable al preview.

    Si el backend falla, las reglas activas de esa cadena quedan en `failed` con
    el mensaje saneado, se registra el fallo en la auditoria y se **relanza**: el
    llamante decide si eso es un 502 o una regla creada que aun no se ha podido
    aplicar.
    """
    objetivo = list(chains) if chains is not None else list(Chain)
    resultados: list[ApplyResult] = []

    for chain in objetivo:
        reglas = _reglas_de_cadena(session, chain)
        specs = [rule_service.spec_de_regla(regla) for regla in reglas if regla.enabled]
        try:
            resultado = backend.apply_ruleset(chain, specs, dry_run=dry_run)
        except FirewallError as exc:
            logger.error("reconciliacion_fallida", chain=chain.value, code=exc.code, exc_info=exc)
            if not dry_run:
                _marcar_fallidas(reglas, exc)
                audit_service.record(
                    session,
                    action=AuditAction.FIREWALL_APPLY,
                    result=AuditResult.FAILURE,
                    user=actor,
                    entity_type="chain",
                    entity_id=chain.value,
                    payload={"error": exc.code, "message": exc.message[:MAX_LAST_ERROR]},
                    client_ip=client_ip,
                    request_id=request_id,
                )
                session.commit()
            raise
        resultados.append(resultado)
        if not dry_run:
            _marcar_aplicadas(reglas)

    aplicado_en = None
    if not dry_run:
        aplicado_en = utcnow()
        audit_service.record(
            session,
            action=AuditAction.FIREWALL_APPLY,
            user=actor,
            entity_type="chain",
            entity_id=",".join(chain.value for chain in objetivo),
            payload={
                "chains": {resultado.chain.value: resultado.applied for resultado in resultados}
            },
            client_ip=client_ip,
            request_id=request_id,
        )
        session.commit()

    return ApplyResponse(
        dry_run=dry_run,
        chains=[
            ChainApply(
                chain=resultado.chain,
                applied=resultado.applied,
                commands=[shlex.join(comando) for comando in resultado.commands],
            )
            for resultado in resultados
        ],
        applied_at=aplicado_en,
    )


def _hay_pendientes(session: Session, chain: Chain) -> bool:
    """Queda algo por aplicar en esta cadena."""
    total = session.scalar(
        select(func.count())
        .select_from(Rule)
        .where(Rule.chain == chain, Rule.sync_state == SyncState.PENDING)
    )
    return bool(total)


def reconciliar_si_auto(
    session: Session,
    backend: FirewallBackend,
    chain: Chain,
    *,
    settings: Settings,
    forzar: bool = False,
    actor: User | None = None,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> None:
    """Aplica la cadena despues de una mutacion, si `AUTO_APPLY` esta activo.

    Existe para que los cinco endpoints que mutan reglas no repitan cada uno su
    version de "y ahora aplica": una copia que se olvide de capturar el error, o
    de mirar el flag, es un bug que solo aparece en un endpoint.

    **Si no hay nada pendiente en la cadena, no se toca el firewall.** Es lo que
    da valor a que `update_rule` solo marque `pending` cuando el cambio afecta a
    la politica: corregir una descripcion deja de reconstruir una cadena entera.
    `forzar` existe para el borrado, que es el unico caso en el que hay trabajo
    que hacer sin que quede ninguna fila pendiente: la que lo pedia ya no esta.

    **El fallo del firewall no tumba la peticion.** La regla ya esta escrita en
    la base de datos, que es la fuente de verdad (ADR-0001), asi que devolver un
    502 diria que no ha pasado nada cuando si ha pasado. Lo que se devuelve es la
    regla con `sync_state = failed` y `last_error` puesto: exactamente el estado
    que el ciclo de vida define para esto, y lo que la tabla del dashboard ya
    sabe pintar. El error completo queda en el log.
    """
    if not settings.auto_apply:
        return
    if not forzar and not _hay_pendientes(session, chain):
        return
    try:
        apply_chains(
            session,
            backend,
            chains=[chain],
            actor=actor,
            client_ip=client_ip,
            request_id=request_id,
        )
    except FirewallError as exc:
        logger.warning("auto_apply_fallido", chain=chain.value, code=exc.code)


# --------------------------------------------------------------------------- #
# Lectura del estado real
# --------------------------------------------------------------------------- #


def _diferencia(
    deseadas: list[RuleSpec], reales: list[RuleSpec]
) -> tuple[Counter[RuleSpec], Counter[RuleSpec]]:
    """Que falta y que sobra, como multiconjuntos.

    Multiconjuntos y no conjuntos porque dos reglas pueden ser identicas en lo
    que hacen y ser dos filas distintas; tratarlas como una sola escondería que
    falta una de las dos.

    La comparacion es entre `RuleSpec`, nunca entre texto: iptables reescribe lo
    que le mandas —reordena selectores, añade `-m tcp`, expande `1.2.3.4` a
    `/32`— asi que comparar lineas da divergencia siempre (ADR-0006).
    """
    balance = Counter(deseadas)
    balance.subtract(Counter(reales))
    faltan = Counter({spec: n for spec, n in balance.items() if n > 0})
    sobran = Counter({spec: -n for spec, n in balance.items() if n < 0})
    return faltan, sobran


def _drift_de_cadena(
    session: Session, backend: FirewallBackend, chain: Chain
) -> tuple[ChainDrift, bool]:
    """Compara una cadena real con lo que la DB dice que deberia ser.

    Devuelve tambien si la cadena se pudo leer, que es como se averigua si el
    scaffold esta puesto: preguntarlo aparte seria leer la cadena dos veces para
    saber lo mismo.
    """
    reglas = _reglas_de_cadena(session, chain)
    activas = [regla for regla in reglas if regla.enabled]
    deseadas = [rule_service.spec_de_regla(regla) for regla in activas]

    def _partir(reglas_ausentes: list[Rule]) -> tuple[list[str], list[str]]:
        """Separa las ausentes en drift de verdad y trabajo pendiente."""
        return (
            [r.uuid for r in reglas_ausentes if r.sync_state is not SyncState.PENDING],
            [r.uuid for r in reglas_ausentes if r.sync_state is SyncState.PENDING],
        )

    try:
        nativas = backend.read_ruleset(chain)
    except FirewallError:
        # La cadena gestionada no existe: no es que falte una regla, es que no
        # hay donde ponerlas. Todo lo activo cuenta como ausente.
        missing, pending = _partir(activas)
        return (
            ChainDrift(
                chain=chain,
                has_drift=bool(missing),
                managed=0,
                missing=missing,
                pending=pending,
            ),
            False,
        )

    reales = [nativa.spec for nativa in nativas if nativa.spec is not None]
    #: Lineas que la aplicacion no sabe expresar y que no son guardianes: reglas
    #: ajenas, o mas expresivas que el modelo (`multiport`, `limit`, negaciones).
    #: Que aparezcan dentro de una cadena gestionada ES drift, y por eso el
    #: parser las conserva en vez de descartarlas en silencio.
    ajenas = [nativa.raw for nativa in nativas if nativa.spec is None and not nativa.is_guardian]

    faltan, sobran = _diferencia(deseadas, reales)

    # De las que faltan, las que nunca se aplicaron no son drift: son trabajo
    # pendiente. Distinguirlas es lo que evita que el banner de drift se
    # encienda cada vez que alguien crea una regla.
    por_spec: dict[RuleSpec, list[Rule]] = {}
    for regla, spec in zip(activas, deseadas, strict=True):
        por_spec.setdefault(spec, []).append(regla)

    ausentes: list[Rule] = []
    for spec, cuantas in faltan.items():
        ausentes.extend(por_spec.get(spec, [])[:cuantas])

    missing, pending = _partir(ausentes)

    sobrantes = list(ajenas)
    restante = Counter(sobran)
    for nativa in nativas:
        if nativa.spec is not None and restante[nativa.spec] > 0:
            restante[nativa.spec] -= 1
            sobrantes.append(nativa.raw)

    desordenadas = not faltan and not sobran and deseadas != reales

    return (
        ChainDrift(
            chain=chain,
            has_drift=bool(missing or sobrantes or desordenadas),
            managed=len(reales),
            missing=missing,
            pending=pending,
            unexpected=sobrantes,
            out_of_order=desordenadas,
        ),
        True,
    )


def _refrescar_contadores(session: Session, backend: FirewallBackend, chain: Chain) -> None:
    """Trae los paquetes y bytes que iptables lleva contados por regla.

    Se hace al pedir el estado y no en un worker aparte porque es la misma
    lectura: el dashboard pregunta "como esta el firewall" y los contadores son
    parte de la respuesta. Que un GET escriba en la base de datos no es bonito,
    pero la alternativa —un endpoint aparte que el frontend tenga que acordarse
    de llamar— es peor, y la escritura es idempotente.

    La clave es el uuid corto, que es lo unico que cabe en el comentario de la
    regla. Un contador sin fila detras se ignora: es una regla que ya se borro.
    """
    try:
        contadores = backend.read_counters(chain)
    except FirewallError:
        return
    if not contadores:
        return
    for regla in _reglas_de_cadena(session, chain):
        contador = contadores.get(regla.uuid[:8])
        if contador is not None:
            regla.hit_count = contador.packets
            regla.bytes_count = contador.bytes


def _actualizar_sync_state(session: Session, chain: Chain, *, hay_drift: bool) -> None:
    """Mueve las reglas entre `applied` y `drift` segun lo que se acaba de ver.

    Solo se tocan esos dos estados, en los dos sentidos. Una regla `pending` o
    `failed` no pasa a `drift` porque su problema ya tiene nombre, y pisarlo
    haria perder el `last_error` que explica que fallo.
    """
    destino = SyncState.DRIFT if hay_drift else SyncState.APPLIED
    origen = SyncState.APPLIED if hay_drift else SyncState.DRIFT
    for regla in _reglas_de_cadena(session, chain):
        if regla.sync_state is origen:
            regla.sync_state = destino


def build_status(
    session: Session, backend: FirewallBackend, *, settings: Settings
) -> FirewallStatus:
    """La foto completa: scaffold, drift por cadena, contadores y pendientes.

    Es lo que alimenta el badge de estado y el banner de drift de la UI. Un
    dashboard de firewall que solo enseñe las reglas de la base de datos esta
    enseñando una intencion, no un estado; esta funcion es la que convierte una
    cosa en la otra.
    """
    cadenas: list[ChainDrift] = []
    scaffold_ok = True

    for chain in Chain:
        _refrescar_contadores(session, backend, chain)
        drift, leida = _drift_de_cadena(session, backend, chain)
        scaffold_ok = scaffold_ok and leida
        cadenas.append(drift)
        _actualizar_sync_state(session, chain, hay_drift=drift.has_drift)

    total = session.scalar(select(func.count()).select_from(Rule)) or 0
    pendientes = (
        session.scalar(
            select(func.count()).select_from(Rule).where(Rule.sync_state == SyncState.PENDING)
        )
        or 0
    )
    ultima = session.scalar(select(func.max(Rule.applied_at)))

    session.commit()

    return FirewallStatus(
        backend=settings.firewall_backend,
        scaffold_ok=scaffold_ok,
        has_drift=any(cadena.has_drift for cadena in cadenas),
        chains=cadenas,
        rules_total=total,
        rules_pending=pendientes,
        last_applied_at=ultima,
    )
