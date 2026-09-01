"""`/health` y `/ready` dicen cosas distintas, y esa diferencia importa."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_responde_sin_tocar_nada(client: TestClient) -> None:
    respuesta = client.get("/health")
    assert respuesta.status_code == 200
    assert respuesta.json() == {"status": "ok"}


def test_health_tambien_esta_bajo_el_prefijo_de_version(client: TestClient) -> None:
    """Una sonda no deberia tener que saber en que version va la API."""
    assert client.get("/api/v1/health").status_code == 200


def test_ready_comprueba_la_base_de_datos(client: TestClient) -> None:
    respuesta = client.get("/ready")
    assert respuesta.status_code == 200

    cuerpo = respuesta.json()
    assert cuerpo["status"] == "ready"
    assert cuerpo["checks"]["database"] == "ok"
    assert cuerpo["firewall_backend"] == "fake"


def test_toda_respuesta_lleva_request_id(client: TestClient) -> None:
    """Es lo que permite buscar en el log la peticion exacta que fallo."""
    respuesta = client.get("/health")
    assert len(respuesta.headers["X-Request-ID"]) == 26


def test_se_respeta_el_request_id_del_cliente(client: TestClient) -> None:
    """Asi se sigue una peticion desde el navegador hasta el log del backend."""
    enviado = "01J8ZQ4T2N6R7V9WXYZ0ABCDEF"
    respuesta = client.get("/health", headers={"X-Request-ID": enviado})
    assert respuesta.headers["X-Request-ID"] == enviado


def test_el_openapi_se_genera(client: TestClient) -> None:
    """Si el esquema no se genera, el frontend no puede derivar sus tipos."""
    respuesta = client.get("/openapi.json")
    assert respuesta.status_code == 200
    assert "/api/v1/health" in respuesta.json()["paths"]
