"""Los endpoints de `/rules`: CRUD, filtros, toggle y reorden.

Se prueban por HTTP y no llamando al servicio a pelo porque la mitad de lo que
hay que verificar vive en la costura: que el rol se exige en la firma, que un
error de dominio sale con el codigo correcto y que lo que se devuelve es lo
normalizado y no lo que se mando.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.firewall.spec import SyncState
from app.models.audit_event import AuditAction, AuditEvent
from app.models.rule import Rule
from app.models.user import User

RULES = "/api/v1/rules"


# --------------------------------------------------------------------------- #
# Alta
# --------------------------------------------------------------------------- #


def test_crear_devuelve_201_y_la_regla_normalizada(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Lo que se guarda es la forma canonica, no la que escribio el usuario.

    `1.2.3.4` y `1.2.3.4/32` son la misma regla; si se guardaran distintas, la
    comparacion con lo que devuelve iptables no cuadraria nunca (ADR-0006).
    """
    respuesta = client.post(
        RULES,
        json={
            "name": "  Bloquear escaner  ",
            "chain": "INPUT",
            "action": "DROP",
            "protocol": "tcp",
            "src_ip": "203.0.113.7",
            "dst_port": "22",
        },
        headers=auth_headers,
    )

    assert respuesta.status_code == 201, respuesta.text
    cuerpo = respuesta.json()
    assert cuerpo["src_ip"] == "203.0.113.7/32"
    assert cuerpo["name"] == "Bloquear escaner"
    # `AUTO_APPLY=true` por defecto: la regla nace `pending` y sale `applied` de
    # la misma peticion. Con el flag a false se quedaria en `pending`, que es el
    # flujo de staging.
    assert cuerpo["sync_state"] == SyncState.APPLIED.value
    assert cuerpo["position"] == 10
    assert cuerpo["created_by"] == "admin"
    # `hashed_password` no puede llegar nunca al cliente, ni anidado.
    assert "hashed_password" not in respuesta.text


def test_las_reglas_se_añaden_al_final_de_su_cadena(
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Las posiciones van de 10 en 10, para dejar hueco a inserciones futuras."""
    primera = crear_regla(name="primera")
    segunda = crear_regla(name="segunda")
    otra_cadena = crear_regla(name="en output", chain="OUTPUT")

    assert primera["position"] == 10
    assert segunda["position"] == 20
    # Cada cadena tiene su propia numeracion: el orden solo significa algo dentro
    # de una cadena.
    assert otra_cadena["position"] == 10


def test_activar_el_log_genera_el_prefijo(crear_regla: Callable[..., dict[str, Any]]) -> None:
    """El CHECK de la columna exige prefijo si hay log; se rellena solo.

    Lleva el uuid corto porque es lo que permitira, en la fase 2, volver de una
    linea de syslog a la fila que la produjo.
    """
    regla = crear_regla(name="con log", log_enabled=True)

    assert regla["log_prefix"] == f"FWD:{regla['uuid'][:8]}"


def test_un_puerto_en_icmp_se_rechaza_con_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """La validacion cruzada de `RuleSpec` protege antes de tocar la red.

    Sin ella, la regla se guardaria y el error saldria al aplicarla, como un 502
    con el stderr de iptables y sin decir que campo estaba mal.
    """
    respuesta = client.post(
        RULES,
        json={
            "name": "imposible",
            "chain": "INPUT",
            "action": "DROP",
            "protocol": "icmp",
            "dst_port": "22",
        },
        headers=auth_headers,
    )

    assert respuesta.status_code == 422
    assert respuesta.json()["error"]["code"] == "invalid_rule"


def test_input_no_admite_interfaz_de_salida(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Cuando el paquete atraviesa INPUT aun no se ha decidido por donde saldra."""
    respuesta = client.post(
        RULES,
        json={
            "name": "sin sentido",
            "chain": "INPUT",
            "action": "DROP",
            "out_interface": "eth0",
        },
        headers=auth_headers,
    )

    assert respuesta.status_code == 422
    assert respuesta.json()["error"]["details"]["campo"] == "out_interface"


def test_una_fecha_sin_zona_se_rechaza_en_el_contrato(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """`expires_at` sin offset da 422, no el 500 de la columna `UtcDateTime`.

    "Caduca a las 22:00" son dos instantes distintos segun quien lo escriba. Es
    el mismo bug de A4, atajado esta vez en la puerta de entrada.
    """
    respuesta = client.post(
        RULES,
        json={
            "name": "temporal",
            "chain": "INPUT",
            "action": "DROP",
            "expires_at": "2026-12-31T22:00:00",
        },
        headers=auth_headers,
    )

    assert respuesta.status_code == 422


# --------------------------------------------------------------------------- #
# Permisos
# --------------------------------------------------------------------------- #


def test_sin_token_no_se_puede_ni_leer(client: TestClient) -> None:
    assert client.get(RULES).status_code == 401


def test_un_viewer_lee_pero_no_escribe(
    client: TestClient,
    viewer_user: User,
    headers_de: Callable[[User], dict[str, str]],
) -> None:
    """El rol `viewer` existe justamente para esto: auditar sin poder cambiar."""
    cabeceras = headers_de(viewer_user)

    assert client.get(RULES, headers=cabeceras).status_code == 200

    respuesta = client.post(
        RULES,
        json={"name": "no deberia", "chain": "INPUT", "action": "DROP"},
        headers=cabeceras,
    )
    assert respuesta.status_code == 403
    assert respuesta.json()["error"]["code"] == "forbidden"


def test_un_operator_si_escribe(
    client: TestClient,
    operator_user: User,
    headers_de: Callable[[User], dict[str, str]],
) -> None:
    respuesta = client.post(
        RULES,
        json={"name": "del operador", "chain": "INPUT", "action": "DROP"},
        headers=headers_de(operator_user),
    )
    assert respuesta.status_code == 201


# --------------------------------------------------------------------------- #
# Listado
# --------------------------------------------------------------------------- #


def test_el_listado_va_ordenado_por_cadena_y_posicion(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """La lista tiene que verse como se va a aplicar: en iptables el orden ES la semantica."""
    crear_regla(name="input 1", chain="INPUT")
    crear_regla(name="output 1", chain="OUTPUT")
    crear_regla(name="input 2", chain="INPUT")

    items = client.get(RULES, headers=auth_headers).json()["items"]

    assert [(item["chain"], item["position"]) for item in items] == [
        ("INPUT", 10),
        ("INPUT", 20),
        ("OUTPUT", 10),
    ]


def test_los_filtros_se_combinan(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    crear_regla(name="ssh entrante", chain="INPUT", description="bloqueo del 22")
    crear_regla(name="dns saliente", chain="OUTPUT")
    desactivada = crear_regla(name="ssh viejo", chain="INPUT")
    client.post(f"{RULES}/{desactivada['uuid']}/toggle", headers=auth_headers)

    def nombres(**filtros: object) -> list[str]:
        respuesta = client.get(RULES, params=filtros, headers=auth_headers)
        assert respuesta.status_code == 200, respuesta.text
        return [item["name"] for item in respuesta.json()["items"]]

    assert nombres(chain="INPUT") == ["ssh entrante", "ssh viejo"]
    assert nombres(chain="INPUT", enabled=True) == ["ssh entrante"]
    assert nombres(q="ssh") == ["ssh entrante", "ssh viejo"]
    # `q` busca tambien en la descripcion, que es donde esta el porque.
    assert nombres(q="bloqueo del 22") == ["ssh entrante"]


def test_la_busqueda_escapa_los_comodines_de_like(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Buscar "8000_" no puede traer "80001".

    `%` y `_` son comodines de LIKE. Sin escaparlos, la busqueda devuelve cosas
    que el usuario no ha pedido y no tiene forma de saber por que.
    """
    crear_regla(name="puerto 8000_x")
    crear_regla(name="puerto 80001")

    items = client.get(RULES, params={"q": "8000_"}, headers=auth_headers).json()["items"]

    assert [item["name"] for item in items] == ["puerto 8000_x"]


def test_la_paginacion_devuelve_el_total_completo(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """El paginador del frontend necesita el total, no solo la pagina."""
    for numero in range(5):
        crear_regla(name=f"regla {numero}")

    cuerpo = client.get(RULES, params={"page": 2, "size": 2}, headers=auth_headers).json()

    assert cuerpo["total"] == 5
    assert cuerpo["page"] == 2
    assert len(cuerpo["items"]) == 2


def test_una_regla_que_no_existe_da_404(client: TestClient, auth_headers: dict[str, str]) -> None:
    respuesta = client.get(f"{RULES}/00000000-0000-0000-0000-000000000000", headers=auth_headers)

    assert respuesta.status_code == 404
    assert respuesta.json()["error"]["code"] == "not_found"


# --------------------------------------------------------------------------- #
# Modificacion
# --------------------------------------------------------------------------- #


def test_el_patch_solo_toca_lo_que_llega(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    regla = crear_regla(name="original", protocol="tcp", dst_port="22", description="el porque")

    cuerpo = client.patch(
        f"{RULES}/{regla['uuid']}", json={"dst_port": "2222"}, headers=auth_headers
    ).json()

    assert cuerpo["dst_port"] == "2222"
    assert cuerpo["name"] == "original"
    assert cuerpo["description"] == "el porque"


def test_cambiar_solo_la_descripcion_no_toca_el_firewall(
    client: TestClient,
    db_session: Session,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """`description` es documentacion, no politica.

    Marcarla como pendiente por corregir una falta de ortografia seria ruido en
    el dashboard y una reaplicacion de la cadena entera para nada. La decision de
    si el cambio importa se toma comparando las dos specs por estructura, que es
    la misma comparacion con la que se detecta el drift.
    """
    regla = crear_regla(name="con historia")
    fila = db_session.scalar(select(Rule).where(Rule.uuid == regla["uuid"]))
    assert fila is not None
    fila.sync_state = SyncState.APPLIED
    db_session.commit()

    cuerpo = client.patch(
        f"{RULES}/{regla['uuid']}",
        json={"description": "ahora si se por que"},
        headers=auth_headers,
    ).json()

    assert cuerpo["sync_state"] == SyncState.APPLIED.value


def test_cambiar_un_selector_si_marca_pendiente(
    client: TestClient,
    db_session: Session,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    regla = crear_regla(name="con historia", protocol="tcp", dst_port="22")
    fila = db_session.scalar(select(Rule).where(Rule.uuid == regla["uuid"]))
    assert fila is not None
    fila.last_error = "algo fallo la vez anterior"
    db_session.commit()

    cuerpo = client.patch(
        f"{RULES}/{regla['uuid']}", json={"dst_port": "2222"}, headers=auth_headers
    ).json()

    # Paso por `pending` y volvio a `applied` en la misma peticion: lo que se ve
    # aqui es que la cadena SI se reconstruyo.
    assert cuerpo["sync_state"] == SyncState.APPLIED.value
    assert cuerpo["applied_at"] != regla["applied_at"]
    # El error de antes describia una regla que ya no existe.
    assert cuerpo["last_error"] is None


def test_mover_una_regla_de_cadena_le_busca_sitio(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """La posicion 10 de INPUT puede estar ocupada en OUTPUT.

    Sin reasignarla, `UniqueConstraint(chain, position)` devolveria un
    IntegrityError de SQLite en vez de un mensaje util.
    """
    crear_regla(name="ya esta en output", chain="OUTPUT")
    viajera = crear_regla(name="se muda", chain="INPUT")

    respuesta = client.patch(
        f"{RULES}/{viajera['uuid']}", json={"chain": "OUTPUT"}, headers=auth_headers
    )

    assert respuesta.status_code == 200, respuesta.text
    assert respuesta.json()["position"] == 20


def test_el_patch_valida_la_regla_completa_no_solo_lo_que_cambia(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Cambiar el protocolo a icmp en una regla que ya tenia puerto es invalido.

    Ningun validador por campo puede verlo: el puerto llega correcto y el
    protocolo tambien. Por eso el PATCH se valida sobre el estado resultante
    completo, no sobre los campos que vienen.
    """
    regla = crear_regla(name="tcp con puerto", protocol="tcp", dst_port="22")

    respuesta = client.patch(
        f"{RULES}/{regla['uuid']}", json={"protocol": "icmp"}, headers=auth_headers
    )

    assert respuesta.status_code == 422
    assert respuesta.json()["error"]["code"] == "invalid_rule"


def test_el_toggle_invierte_y_reaplica(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Desactivar no borra: la regla sigue, con su descripcion, y el renderer la omite."""
    regla = crear_regla(name="sospechosa")

    apagada = client.post(f"{RULES}/{regla['uuid']}/toggle", headers=auth_headers).json()
    encendida = client.post(f"{RULES}/{regla['uuid']}/toggle", headers=auth_headers).json()

    assert apagada["enabled"] is False
    assert apagada["sync_state"] == SyncState.APPLIED.value
    assert encendida["enabled"] is True


def test_borrar_devuelve_204_y_la_regla_desaparece(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    regla = crear_regla(name="efimera")

    assert client.delete(f"{RULES}/{regla['uuid']}", headers=auth_headers).status_code == 204
    assert client.get(f"{RULES}/{regla['uuid']}", headers=auth_headers).status_code == 404


# --------------------------------------------------------------------------- #
# Reorden
# --------------------------------------------------------------------------- #


def test_el_reorden_reescribe_las_posiciones_de_diez_en_diez(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """El caso que obliga a las dos fases.

    Las tres reglas ocupan 10, 20 y 30, y el nuevo orden vuelve a usar 10, 20 y
    30. Reasignarlas de una en una haria que el primer UPDATE chocara con una
    fila que todavia no se ha movido: `UniqueConstraint(chain, position)` se
    comprueba en cada UPDATE, no al final de la transaccion.
    """
    a = crear_regla(name="a")
    b = crear_regla(name="b")
    c = crear_regla(name="c")

    respuesta = client.post(
        f"{RULES}/reorder",
        json={"uuids": [c["uuid"], a["uuid"], b["uuid"]]},
        headers=auth_headers,
    )

    assert respuesta.status_code == 200, respuesta.text
    assert [(item["name"], item["position"]) for item in respuesta.json()] == [
        ("c", 10),
        ("a", 20),
        ("b", 30),
    ]


def test_un_reorden_parcial_se_rechaza_con_409(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """Falta una regla: las que quedan fuera conservarian posiciones que chocan."""
    a = crear_regla(name="a")
    b = crear_regla(name="b")
    crear_regla(name="c")

    respuesta = client.post(
        f"{RULES}/reorder", json={"uuids": [b["uuid"], a["uuid"]]}, headers=auth_headers
    )

    assert respuesta.status_code == 409
    assert respuesta.json()["error"]["code"] == "conflict"
    assert respuesta.json()["error"]["details"]["faltan"]


def test_no_se_pueden_mezclar_cadenas_en_un_reorden(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    """El orden solo significa algo dentro de una cadena."""
    entrada = crear_regla(name="entrada", chain="INPUT")
    salida = crear_regla(name="salida", chain="OUTPUT")

    respuesta = client.post(
        f"{RULES}/reorder",
        json={"uuids": [entrada["uuid"], salida["uuid"]]},
        headers=auth_headers,
    )

    assert respuesta.status_code == 422


def test_un_uuid_desconocido_en_el_reorden_da_404(
    client: TestClient,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
) -> None:
    regla = crear_regla(name="a")

    respuesta = client.post(
        f"{RULES}/reorder",
        json={"uuids": [regla["uuid"], "00000000-0000-0000-0000-000000000000"]},
        headers=auth_headers,
    )

    assert respuesta.status_code == 404


def test_reorder_no_se_confunde_con_un_uuid(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """`/rules/reorder` va declarado antes que `/rules/{uuid}`.

    Al reves, esta peticion entraria por el handler de una regla concreta con el
    uuid literal "reorder" y devolveria 404 en vez de hacer nada.
    """
    respuesta = client.post(f"{RULES}/reorder", json={"uuids": []}, headers=auth_headers)

    # 422 por la lista vacia, que es la validacion del schema: la ruta si existe.
    assert respuesta.status_code == 422


# --------------------------------------------------------------------------- #
# Auditoria
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("metodo", "sufijo", "cuerpo", "accion"),
    [
        ("patch", "", {"name": "otro nombre"}, AuditAction.RULE_UPDATE),
        ("post", "/toggle", None, AuditAction.RULE_TOGGLE),
        ("delete", "", None, AuditAction.RULE_DELETE),
    ],
)
def test_toda_mutacion_queda_auditada(
    client: TestClient,
    db_session: Session,
    auth_headers: dict[str, str],
    crear_regla: Callable[..., dict[str, Any]],
    metodo: str,
    sufijo: str,
    cuerpo: dict[str, Any] | None,
    accion: AuditAction,
) -> None:
    """Es la tabla que separa "una app que toca iptables" de una herramienta de seguridad."""
    regla = crear_regla(name="auditada")

    # `client.request` y no `client.delete`: httpx no acepta cuerpo en el
    # atajo de DELETE, y aqui hace falta la misma llamada para los tres verbos.
    client.request(
        metodo.upper(), f"{RULES}/{regla['uuid']}{sufijo}", json=cuerpo, headers=auth_headers
    )

    eventos = db_session.scalars(select(AuditEvent).where(AuditEvent.action == accion)).all()
    assert len(eventos) == 1
    assert eventos[0].entity_id == regla["uuid"]
    assert eventos[0].username == "admin"


def test_el_alta_guarda_el_estado_completo_en_la_auditoria(
    db_session: Session, crear_regla: Callable[..., dict[str, Any]]
) -> None:
    """El payload se enseña entero en el dashboard, asi que va sin secretos y en JSON plano."""
    crear_regla(name="auditada", protocol="tcp", dst_port="22")

    evento = db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == AuditAction.RULE_CREATE)
    )
    assert evento is not None
    assert evento.payload["name"] == "auditada"
    assert evento.payload["chain"] == "INPUT"
    assert evento.payload["dst_port"] == "22"
