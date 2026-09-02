"""Los endpoints de `/firewall`: apply, preview y status.

Aqui se prueba el corazon del diseño: que aplicar signifique siempre reconstruir
la cadena entera desde la base de datos (ADR-0002), que el preview enseñe
exactamente lo que el apply ejecutaria, y que el drift se detecte comparando
estructuras y no texto (ADR-0006).

Todo contra el `FakeFirewallBackend`, que no reimplementa nada: renderiza con el
renderer de verdad y lee de vuelta con el parser de verdad. Lo unico que finge es
el sistema operativo que habria en medio.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_settings_dep
from app.core.config import Settings
from app.firewall.fake import FakeFirewallBackend
from app.firewall.spec import Action, Chain, Protocol, RuleSpec, SyncState
from app.main import create_app
from app.models.audit_event import AuditAction, AuditEvent
from app.models.rule import Rule
from app.models.user import User

RULES = "/api/v1/rules"
FIREWALL = "/api/v1/firewall"


@pytest.fixture
def cliente_sin_auto_apply(settings: Settings, db_session: Session) -> Iterator[TestClient]:
    """Un cliente con `AUTO_APPLY=false`: el flujo de staging tipo Terraform.

    Es el mismo codigo con un flag distinto, y esa es justamente la propiedad que
    hay que verificar: que apagar el automatismo no cambie ninguna ruta, solo el
    momento en que se aplica.
    """
    ajustes = settings.model_copy(update={"auto_apply": False})
    application = create_app(ajustes)

    def _db() -> Iterator[Session]:
        yield db_session

    application.dependency_overrides[get_db] = _db
    application.dependency_overrides[get_settings_dep] = lambda: ajustes
    with TestClient(application) as cliente:
        yield cliente


def _comandos(respuesta: dict[str, Any], chain: str) -> list[str]:
    for cadena in respuesta["chains"]:
        if cadena["chain"] == chain:
            comandos: list[str] = cadena["commands"]
            return comandos
    raise AssertionError(f"la respuesta no trae la cadena {chain}")


def _drift(respuesta: dict[str, Any], chain: str) -> dict[str, Any]:
    for cadena in respuesta["chains"]:
        if cadena["chain"] == chain:
            resultado: dict[str, Any] = cadena
            return resultado
    raise AssertionError(f"el status no trae la cadena {chain}")


# --------------------------------------------------------------------------- #
# Preview
# --------------------------------------------------------------------------- #


def test_el_preview_no_ejecuta_nada(
    cliente_sin_auto_apply: TestClient,
    auth_headers: dict[str, str],
) -> None:
    """Ver antes de ejecutar: la mitigacion nº2 del problema del auto-bloqueo."""
    cliente_sin_auto_apply.post(
        RULES,
        json={"name": "bloqueo", "chain": "INPUT", "action": "DROP", "src_ip": "203.0.113.9"},
        headers=auth_headers,
    )

    cuerpo = cliente_sin_auto_apply.get(f"{FIREWALL}/preview", headers=auth_headers).json()

    assert cuerpo["dry_run"] is True
    assert cuerpo["applied_at"] is None
    assert any("203.0.113.9/32" in comando for comando in _comandos(cuerpo, "INPUT"))

    # Y el firewall sigue sin la regla: solo estan los guardianes.
    estado = cliente_sin_auto_apply.get(f"{FIREWALL}/status", headers=auth_headers).json()
    assert _drift(estado, "INPUT")["managed"] == 0


def test_el_preview_enseña_lo_mismo_que_ejecutaria_el_apply(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Es la misma funcion con `dry_run=True`, y este test lo ata.

    Si preview y apply fueran dos caminos, podrian divergir sin que nadie se
    enterara, y entonces el preview dejaria de servir para lo unico para lo que
    existe.
    """
    crear_regla(name="una", src_ip="10.0.0.1")
    crear_regla(name="otra", chain="OUTPUT", dst_ip="10.0.0.2")

    previo = client.get(f"{FIREWALL}/preview", headers=auth_headers).json()
    aplicado = client.post(f"{FIREWALL}/apply", headers=auth_headers).json()

    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        assert _comandos(previo, chain) == _comandos(aplicado, chain)


def test_cada_cadena_se_vacia_antes_de_reconstruirse(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """El `-F` de cabecera es lo que hace la operacion idempotente.

    Sin el, aplicar dos veces dejaria la regla duplicada, y el estado final
    dependeria de cuantas veces se ha pulsado el boton.
    """
    crear_regla(name="una")

    cuerpo = client.get(f"{FIREWALL}/preview", headers=auth_headers).json()
    comandos = _comandos(cuerpo, "INPUT")

    assert comandos[0] == "iptables -F FWDASH_INPUT"
    # Y los guardianes van antes que las reglas del usuario: si el usuario
    # bloquea su propio puerto de gestion, el guardian ya ha aceptado el paquete.
    assert "fwdash:guardian:conntrack" in comandos[1]
    assert "fwdash:guardian:management" in comandos[3]


# --------------------------------------------------------------------------- #
# Apply
# --------------------------------------------------------------------------- #


def test_apply_deja_las_reglas_aplicadas(
    cliente_sin_auto_apply: TestClient,
    db_session: Session,
    auth_headers: dict[str, str],
) -> None:
    cliente_sin_auto_apply.post(
        RULES,
        json={"name": "bloqueo", "chain": "INPUT", "action": "DROP"},
        headers=auth_headers,
    )
    fila = db_session.scalar(select(Rule))
    assert fila is not None
    assert fila.sync_state is SyncState.PENDING
    assert fila.applied_at is None

    respuesta = cliente_sin_auto_apply.post(f"{FIREWALL}/apply", headers=auth_headers)

    assert respuesta.status_code == 200, respuesta.text
    assert respuesta.json()["dry_run"] is False
    assert respuesta.json()["applied_at"] is not None
    db_session.refresh(fila)
    assert fila.sync_state is SyncState.APPLIED
    assert fila.applied_at is not None


def test_una_regla_desactivada_tambien_queda_aplicada(
    client: TestClient,
    db_session: Session,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """`applied` significa "la DB y iptables dicen lo mismo".

    De una regla desactivada las dos dicen lo mismo: que no esta. Dejarla en
    `pending` para siempre haria que el badge del dashboard nunca se pusiera en
    verde teniendo una sola regla apagada.
    """
    regla = crear_regla(name="apagada")
    client.post(f"{RULES}/{regla['uuid']}/toggle", headers=auth_headers)

    fila = db_session.scalar(select(Rule).where(Rule.uuid == regla["uuid"]))
    assert fila is not None
    db_session.refresh(fila)
    assert fila.enabled is False
    assert fila.sync_state is SyncState.APPLIED


def test_aplicar_dos_veces_deja_la_cadena_igual(
    client: TestClient,
    api_app: FastAPI,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Idempotencia: el estado final solo depende de la base de datos."""
    crear_regla(name="una", src_ip="10.0.0.1")

    client.post(f"{FIREWALL}/apply", headers=auth_headers)
    primera = api_app.state.firewall.read_ruleset(Chain.INPUT)
    client.post(f"{FIREWALL}/apply", headers=auth_headers)
    segunda = api_app.state.firewall.read_ruleset(Chain.INPUT)

    assert [regla.raw for regla in primera] == [regla.raw for regla in segunda]


def test_el_apply_queda_auditado(
    client: TestClient, db_session: Session, auth_headers: dict[str, str]
) -> None:
    client.post(f"{FIREWALL}/apply", headers=auth_headers)

    eventos = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == AuditAction.FIREWALL_APPLY)
    ).all()
    assert eventos
    assert eventos[-1].username == "admin"


# --------------------------------------------------------------------------- #
# Auto-apply
# --------------------------------------------------------------------------- #


def test_con_auto_apply_la_regla_nace_aplicada(
    api_app: FastAPI, crear_regla: Callable[..., dict[str, Any]]
) -> None:
    """El caso por defecto: crear una regla la pone en el firewall."""
    regla = crear_regla(name="inmediata", src_ip="198.51.100.4")

    assert regla["sync_state"] == SyncState.APPLIED.value
    nativas = api_app.state.firewall.read_ruleset(Chain.INPUT)
    assert any("198.51.100.4/32" in nativa.raw for nativa in nativas)


def test_sin_auto_apply_la_regla_se_queda_pendiente(
    cliente_sin_auto_apply: TestClient, auth_headers: dict[str, str]
) -> None:
    """`AUTO_APPLY=false` da un flujo de staging cambiando un flag, no reescribiendo."""
    respuesta = cliente_sin_auto_apply.post(
        RULES,
        json={"name": "en espera", "chain": "INPUT", "action": "DROP"},
        headers=auth_headers,
    )

    assert respuesta.status_code == 201
    assert respuesta.json()["sync_state"] == SyncState.PENDING.value


def test_borrar_una_regla_la_quita_de_la_cadena(
    client: TestClient,
    api_app: FastAPI,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """El caso que obliga a `forzar` en el auto-apply.

    Al borrar, la fila que pedia el cambio ya no existe, asi que no queda nada
    marcado como `pending`. Sin forzar la reconciliacion, la regla seguiria en
    iptables hasta el siguiente apply manual.
    """
    regla = crear_regla(name="efimera", src_ip="198.51.100.5")
    assert any(
        "198.51.100.5/32" in nativa.raw
        for nativa in api_app.state.firewall.read_ruleset(Chain.INPUT)
    )

    client.delete(f"{RULES}/{regla['uuid']}", headers=auth_headers)

    assert not any(
        "198.51.100.5/32" in nativa.raw
        for nativa in api_app.state.firewall.read_ruleset(Chain.INPUT)
    )


def test_si_el_firewall_falla_la_regla_se_crea_igual(
    client: TestClient, api_app: FastAPI, auth_headers: dict[str, str]
) -> None:
    """Un 502 aqui diria que no ha pasado nada, y si ha pasado: la regla existe.

    Lo que se devuelve es 201 con `sync_state = failed` y `last_error` puesto,
    que es exactamente el estado que el ciclo de vida define para esto y lo que
    la tabla del dashboard ya sabe pintar.
    """
    # Un fake sin `ensure_scaffold` falla igual que iptables sin las cadenas.
    api_app.state.firewall = FakeFirewallBackend()

    respuesta = client.post(
        RULES,
        json={"name": "no se podra aplicar", "chain": "INPUT", "action": "DROP"},
        headers=auth_headers,
    )

    assert respuesta.status_code == 201, respuesta.text
    cuerpo = respuesta.json()
    assert cuerpo["sync_state"] == SyncState.FAILED.value
    assert "No chain/target/match by that name" in cuerpo["last_error"]


def test_el_apply_explicito_si_devuelve_502(
    client: TestClient, api_app: FastAPI, auth_headers: dict[str, str]
) -> None:
    """La diferencia con el auto-apply: aqui lo unico que se ha pedido es aplicar.

    Decir que ha ido bien cuando no ha ido bien seria mentir sobre lo unico que
    el cliente queria saber.
    """
    api_app.state.firewall = FakeFirewallBackend()

    respuesta = client.post(f"{FIREWALL}/apply", headers=auth_headers)

    assert respuesta.status_code == 502
    assert respuesta.json()["error"]["code"] == "firewall_command_failed"


# --------------------------------------------------------------------------- #
# Status y drift
# --------------------------------------------------------------------------- #


def test_sin_nadie_tocando_nada_no_hay_drift(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    crear_regla(name="una", src_ip="10.0.0.1", protocol="tcp", dst_port="443")
    crear_regla(name="otra", chain="FORWARD", action="ACCEPT")

    cuerpo = client.get(f"{FIREWALL}/status", headers=auth_headers).json()

    assert cuerpo["scaffold_ok"] is True
    assert cuerpo["has_drift"] is False
    assert cuerpo["rules_total"] == 2
    assert cuerpo["rules_pending"] == 0
    assert cuerpo["last_applied_at"] is not None


def test_una_regla_sin_aplicar_no_es_drift(
    cliente_sin_auto_apply: TestClient, auth_headers: dict[str, str]
) -> None:
    """Es la distincion que evita que el banner se encienda al crear una regla.

    "Esta en la DB y no en iptables" tiene dos causas muy distintas: no se ha
    aplicado todavia, o alguien toco el firewall por fuera. Solo la segunda es
    drift.
    """
    cliente_sin_auto_apply.post(
        RULES, json={"name": "nueva", "chain": "INPUT", "action": "DROP"}, headers=auth_headers
    )

    cuerpo = cliente_sin_auto_apply.get(f"{FIREWALL}/status", headers=auth_headers).json()

    assert cuerpo["has_drift"] is False
    assert cuerpo["rules_pending"] == 1
    assert len(_drift(cuerpo, "INPUT")["pending"]) == 1
    assert _drift(cuerpo, "INPUT")["missing"] == []


def test_una_regla_con_el_log_activado_no_es_drift(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """El renderer emite DOS lineas por regla con log, y las dos son suyas.

    Regresion de A6: la mitad `-j LOG` llegaba a la comparacion con `spec = None`
    y sin etiqueta de guardian, que es el perfil exacto de una regla ajena. El
    banner de drift acusaba de haber tocado el firewall por fuera a quien acababa
    de crear una regla con el log encendido, y aplicar de nuevo no lo arreglaba:
    el apply volvia a escribir la misma linea.
    """
    crear_regla(name="con log", log_enabled=True, log_prefix="TEST: ")

    cuerpo = client.get(f"{FIREWALL}/status", headers=auth_headers).json()

    assert cuerpo["has_drift"] is False
    assert _drift(cuerpo, "INPUT")["unexpected"] == []


def test_una_regla_borrada_a_mano_es_drift(
    client: TestClient,
    api_app: FastAPI,
    db_session: Session,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Alguien vacio la cadena por fuera: la regla se creia aplicada y no esta."""
    regla = crear_regla(name="la borraron", src_ip="10.0.0.1")
    api_app.state.firewall.apply_ruleset(Chain.INPUT, [])

    cuerpo = client.get(f"{FIREWALL}/status", headers=auth_headers).json()

    assert cuerpo["has_drift"] is True
    assert _drift(cuerpo, "INPUT")["missing"] == [regla["uuid"]]
    # Y la fila lo refleja: `applied` -> `drift`.
    fila = db_session.scalar(select(Rule).where(Rule.uuid == regla["uuid"]))
    assert fila is not None
    db_session.refresh(fila)
    assert fila.sync_state is SyncState.DRIFT


def test_una_regla_ajena_en_la_cadena_es_drift(
    client: TestClient, api_app: FastAPI, auth_headers: dict[str, str]
) -> None:
    """Una regla que no sale de la base de datos no puede estar en una cadena gestionada.

    Se devuelve su linea original, no una interpretacion: es lo que hay que
    enseñar cuando toca explicar por que la cadena no cuadra.
    """
    intrusa = RuleSpec(
        chain=Chain.INPUT, action=Action.ACCEPT, protocol=Protocol.TCP, dst_port="4444"
    )
    api_app.state.firewall.apply_ruleset(Chain.INPUT, [intrusa])

    cuerpo = client.get(f"{FIREWALL}/status", headers=auth_headers).json()

    assert cuerpo["has_drift"] is True
    sobrantes = _drift(cuerpo, "INPUT")["unexpected"]
    assert len(sobrantes) == 1
    assert "4444" in sobrantes[0]


def test_el_mismo_conjunto_en_otro_orden_es_drift(
    client: TestClient,
    api_app: FastAPI,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """En iptables el orden ES la semantica: gana la primera regla que hace match.

    Estan las dos reglas y no sobra ninguna, asi que un `set` diria que todo va
    bien. Por eso la comparacion es de listas.
    """
    crear_regla(name="primera", src_ip="10.0.0.1")
    crear_regla(name="segunda", src_ip="10.0.0.2")
    backend = api_app.state.firewall

    # Alguien reescribe la cadena con las mismas reglas al reves.
    actuales = [nativa.spec for nativa in backend.read_ruleset(Chain.INPUT) if nativa.spec]
    backend.apply_ruleset(Chain.INPUT, list(reversed(actuales)))

    cuerpo = client.get(f"{FIREWALL}/status", headers=auth_headers).json()
    entrada = _drift(cuerpo, "INPUT")

    assert entrada["out_of_order"] is True
    assert entrada["has_drift"] is True
    # Ni falta ni sobra nada: un `set` habria dicho que todo va bien.
    assert entrada["missing"] == []
    assert entrada["unexpected"] == []


def test_los_contadores_se_refrescan_al_pedir_el_estado(
    client: TestClient,
    api_app: FastAPI,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Sin esto, `FIREWALL_BACKEND=fake` da una UI con todos los contadores a cero.

    Que es una demo pobre y ademas esconde los bugs de formateo de numeros
    grandes.
    """
    regla = crear_regla(name="con trafico", src_ip="10.0.0.1")
    api_app.state.firewall.simulate_traffic(regla["uuid"], packets=1234, bytes=567890)

    client.get(f"{FIREWALL}/status", headers=auth_headers)
    cuerpo = client.get(f"{RULES}/{regla['uuid']}", headers=auth_headers).json()

    assert cuerpo["hit_count"] == 1234
    assert cuerpo["bytes_count"] == 567890


def test_sin_scaffold_el_estado_lo_dice(
    client: TestClient, api_app: FastAPI, auth_headers: dict[str, str]
) -> None:
    """Es el primer sitio donde mirar cuando nada funciona en la VM."""
    api_app.state.firewall = FakeFirewallBackend()

    cuerpo = client.get(f"{FIREWALL}/status", headers=auth_headers).json()

    assert cuerpo["scaffold_ok"] is False


# --------------------------------------------------------------------------- #
# Permisos
# --------------------------------------------------------------------------- #


def test_un_viewer_ve_el_estado_pero_no_aplica(
    client: TestClient,
    viewer_user: User,
    headers_de: Callable[[User], dict[str, str]],
) -> None:
    """El preview tambien pide `operator`: enseña el puerto y el rango de gestion.

    No es por las reglas —un viewer ya puede listarlas— sino por los guardianes,
    que son topologia de la red de administracion.
    """
    cabeceras = headers_de(viewer_user)

    assert client.get(f"{FIREWALL}/status", headers=cabeceras).status_code == 200
    assert client.get(f"{FIREWALL}/preview", headers=cabeceras).status_code == 403
    assert client.post(f"{FIREWALL}/apply", headers=cabeceras).status_code == 403


def test_sin_token_no_hay_estado(client: TestClient) -> None:
    assert client.get(f"{FIREWALL}/status").status_code == 401
