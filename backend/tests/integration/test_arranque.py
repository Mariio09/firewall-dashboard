"""El arranque deja la politica PUESTA, no solo guardada. Paso C2.

Hasta aqui, "reiniciar" significaba perder el firewall: el kernel arranca sin las
cadenas gestionadas, `ensure_scaffold()` las crea vacias —montar no es poblar,
invariante que descubrio el contrato de B5— y las reglas seguian vivas solo en
SQLite hasta que alguien llamaba a `/firewall/apply` a mano. Eso es un dashboard
que dice `applied` sobre una cadena vacia: exactamente la clase de mentira contra
la que existe la deteccion de drift.

Cada test de aqui mide el EFECTO —que la regla este en la cadena, o que no este—
y no que una funcion se haya llamado. Y los dos que afirman "esta puesto" llevan
pegada la contraprueba de que no estaria sin el mecanismo que se prueba: un
backend montado a mano, sin `lifespan`, tiene la cadena vacia.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import build_firewall_backend
from app.core.config import Settings
from app.core.exceptions import FirewallCommandError
from app.firewall.base import FirewallBackend
from app.firewall.fake import FakeFirewallBackend
from app.firewall.spec import ApplyResult, Chain, RuleSpec, SyncState
from app.main import create_app
from app.models.audit_event import AuditAction, AuditEvent
from app.models.rule import Rule


def _de_usuario(firewall: FirewallBackend, chain: Chain = Chain.INPUT) -> list[str]:
    """Las lineas de la cadena que NO son guardianes."""
    return [nativa.raw for nativa in firewall.read_ruleset(chain) if not nativa.is_guardian]


def _guardianes(firewall: FirewallBackend, chain: Chain = Chain.INPUT) -> list[str]:
    return [nativa.raw for nativa in firewall.read_ruleset(chain) if nativa.is_guardian]


def _reiniciar(settings: Settings, session_factory: sessionmaker[Session]) -> FirewallBackend:
    """Arranca una aplicacion NUEVA sobre la misma base de datos y la para.

    Es lo mas parecido a reiniciar el servicio que se puede hacer en un test: el
    proceso es el mismo, pero la aplicacion y su backend de firewall nacen
    limpios, que es justo lo que pasa tras un `systemctl restart`.
    """
    aplicacion = create_app(settings, session_factory=session_factory)
    with TestClient(aplicacion):
        pass
    backend: FirewallBackend = aplicacion.state.firewall
    return backend


# --------------------------------------------------------------------------- #
# Lo que se restaura
# --------------------------------------------------------------------------- #


def test_al_reiniciar_la_politica_guardada_vuelve_al_firewall(
    settings: Settings,
    session_factory: sessionmaker[Session],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """El caso que da sentido al paso: la regla sobrevive al reinicio."""
    crear_regla(name="sobrevive", src_ip="198.51.100.10")

    reiniciado = _reiniciar(settings, session_factory)

    assert any("198.51.100.10/32" in linea for linea in _de_usuario(reiniciado))

    # Contraprueba: sin el arranque, esa misma cadena esta vacia. Sin ella, el
    # assert de arriba pasaria igual si el fake devolviera siempre algo.
    a_mano = build_firewall_backend(settings)
    a_mano.ensure_scaffold()
    assert a_mano.read_ruleset(Chain.INPUT) == []


def test_los_guardianes_estan_puestos_antes_de_que_exista_ninguna_regla(
    settings: Settings, session_factory: sessionmaker[Session]
) -> None:
    """Con la politica vacia tambien se reconcilia, y no es trabajo de mas.

    Lo que escribe `apply_chains` cuando no hay ninguna regla son los guardianes.
    Tenerlos desde el arranque significa que el puerto de gestion esta protegido
    ANTES de que exista la primera regla capaz de cerrarlo; saltarse el apply por
    estar la politica vacia ahorraria tres comandos y dejaria esa ventana
    abierta.
    """
    reiniciado = _reiniciar(settings, session_factory)

    assert _guardianes(reiniciado) != []
    assert _de_usuario(reiniciado) == []


def test_la_reconciliacion_de_arranque_actualiza_el_estado_en_la_base_de_datos(
    settings: Settings,
    session_factory: sessionmaker[Session],
    db_session: Session,
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """No basta con escribir en iptables: la fila tiene que dejar de decir `pending`.

    Se fuerza el estado a `pending` a mano —es el estado en el que quedan las
    reglas creadas con `AUTO_APPLY=false`, o las que fallaron al aplicarse— y el
    arranque tiene que resolverlo. Si solo se mirase la cadena, un arranque que
    aplica pero no marca pasaria por bueno y el dashboard seguiria enseñando un
    badge de "pendiente" sobre una regla que ya esta puesta.
    """
    creada = crear_regla(name="pendiente al arrancar", src_ip="198.51.100.13")
    fila = db_session.scalar(select(Rule).where(Rule.uuid == creada["uuid"]))
    assert fila is not None
    fila.sync_state = SyncState.PENDING
    db_session.commit()

    _reiniciar(settings, session_factory)

    db_session.expire_all()
    refrescada = db_session.scalar(select(Rule).where(Rule.uuid == creada["uuid"]))
    assert refrescada is not None
    assert refrescada.sync_state is SyncState.APPLIED


def test_el_apply_del_arranque_queda_auditado_con_nombre(
    settings: Settings,
    session_factory: sessionmaker[Session],
    db_session: Session,
) -> None:
    """Una auditoria ambigua no es una auditoria.

    La fila del arranque no tiene usuario, porque no hay nadie. Si se dejara el
    `username` vacio quedaria idéntica a la de un apply hecho por una cuenta que
    despues se borro —el `SET NULL` de la clave foranea deja justo eso—, y la
    tabla no distinguiria "lo hizo el servicio al arrancar" de "no se sabe".
    """
    _reiniciar(settings, session_factory)

    db_session.expire_all()
    eventos = list(
        db_session.scalars(
            select(AuditEvent).where(AuditEvent.action == AuditAction.FIREWALL_APPLY)
        )
    )

    assert eventos, "el arranque aplico y no dejo rastro en la auditoria"
    assert eventos[-1].username == "sistema:arranque"
    assert eventos[-1].user_id is None


# --------------------------------------------------------------------------- #
# Lo que NO se hace
# --------------------------------------------------------------------------- #


def test_sin_auto_apply_el_arranque_no_escribe_en_el_firewall(
    settings: Settings,
    session_factory: sessionmaker[Session],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """`AUTO_APPLY=false` significa "no escribas por tu cuenta", y arrancar no es una excepcion.

    Quien apaga el auto-apply quiere un flujo de staging: escribir la politica y
    decidir cuando llega al firewall. Un arranque que aplicase igual le quitaria
    esa decision en el peor momento posible, un reinicio no planeado.
    """
    crear_regla(name="en espera", src_ip="198.51.100.11")

    sin_auto = settings.model_copy(update={"auto_apply": False})
    reiniciado = _reiniciar(sin_auto, session_factory)

    assert reiniciado.read_ruleset(Chain.INPUT) == []


# --------------------------------------------------------------------------- #
# Cuando el firewall falla (ADR-0015 y ADR-0018)
# --------------------------------------------------------------------------- #


class _FirewallQueFallaAlAplicar(FakeFirewallBackend):
    """Monta las cadenas pero no sabe aplicar. Es el fallo mas incomodo posible.

    `ensure_scaffold()` funciona, asi que la aplicacion cree tener firewall; lo
    que revienta es la reconciliacion. Un backend que fallara ya al montar seria
    un caso mas facil y lo cubre `firewall_no_disponible`.
    """

    def apply_ruleset(
        self, chain: Chain, specs: Sequence[RuleSpec], *, dry_run: bool = False
    ) -> ApplyResult:
        raise FirewallCommandError("iptables no responde")


def test_si_la_reconciliacion_falla_la_aplicacion_arranca_igual(
    settings: Settings,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un dashboard que no arranca cuando el firewall falla no sirve para diagnosticarlo.

    Es la misma decision del ADR-0015, extendida al apply del arranque: el error
    se registra, las reglas afectadas quedan en `failed` con su motivo, y la
    aplicacion sigue en pie para poder contarlo por la API.
    """
    monkeypatch.setattr(
        "app.main.build_firewall_backend", lambda _ajustes: _FirewallQueFallaAlAplicar()
    )

    aplicacion = create_app(settings, session_factory=session_factory)
    with TestClient(aplicacion) as cliente:
        assert cliente.get("/api/v1/health").status_code == 200
        # Y el backend sigue publicado: el fallo fue de la reconciliacion, no del
        # montaje, asi que `/firewall/status` puede contar lo que pasa.
        assert aplicacion.state.firewall is not None


def test_una_regla_que_no_se_pudo_aplicar_al_arrancar_queda_marcada(
    settings: Settings,
    session_factory: sessionmaker[Session],
    db_session: Session,
    crear_regla: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """El fallo no se traga en silencio: queda en la fila y en `last_error`."""
    creada = crear_regla(name="no se podra aplicar", src_ip="198.51.100.14")

    monkeypatch.setattr(
        "app.main.build_firewall_backend", lambda _ajustes: _FirewallQueFallaAlAplicar()
    )
    _reiniciar(settings, session_factory)

    db_session.expire_all()
    fila = db_session.scalar(select(Rule).where(Rule.uuid == creada["uuid"]))
    assert fila is not None
    assert fila.sync_state is SyncState.FAILED
    assert fila.last_error
