"""Todos los errores de la API tienen la misma forma. Sin excepciones.

Que el frontend solo tenga que entender un sobre es lo que permite un unico
interceptor en `api/client.ts` en vez de un `if` por endpoint.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.exceptions import ConflictError, InvalidRuleError


def _forma_de_error(cuerpo: dict) -> None:
    assert set(cuerpo) == {"error"}
    assert set(cuerpo["error"]) == {"code", "message", "details", "request_id"}


def test_una_ruta_inexistente_devuelve_el_sobre_estandar(client: TestClient) -> None:
    respuesta = client.get("/api/v1/no-existe")
    assert respuesta.status_code == 404

    cuerpo = respuesta.json()
    _forma_de_error(cuerpo)
    assert cuerpo["error"]["code"] == "not_found"
    assert cuerpo["error"]["request_id"] == respuesta.headers["X-Request-ID"]


def test_un_metodo_no_permitido_tambien(client: TestClient) -> None:
    respuesta = client.post("/health")
    assert respuesta.status_code == 405
    assert respuesta.json()["error"]["code"] == "method_not_allowed"


def test_un_error_de_dominio_conserva_codigo_y_detalles(
    api_app: FastAPI, client: TestClient
) -> None:
    """Un servicio lanza `InvalidRuleError` y el handler lo traduce solo.

    Es lo que permite que `services/` no importe nunca `fastapi`: la traduccion
    a HTTP vive en un unico sitio.
    """

    @api_app.get("/_test/regla-invalida")
    def _ruta() -> None:
        raise InvalidRuleError(
            "El puerto '99999' esta fuera del rango valido (1-65535).",
            details={"field": "dst_port"},
        )

    respuesta = client.get("/_test/regla-invalida")
    assert respuesta.status_code == 422

    cuerpo = respuesta.json()
    _forma_de_error(cuerpo)
    assert cuerpo["error"]["code"] == "invalid_rule"
    assert cuerpo["error"]["details"] == {"field": "dst_port"}


def test_cada_error_de_dominio_lleva_su_propio_status(api_app: FastAPI, client: TestClient) -> None:
    @api_app.get("/_test/conflicto")
    def _ruta() -> None:
        raise ConflictError("La posicion 10 ya esta ocupada en INPUT.")

    respuesta = client.get("/_test/conflicto")
    assert respuesta.status_code == 409
    assert respuesta.json()["error"]["code"] == "conflict"


def test_una_excepcion_inesperada_no_filtra_la_traza(api_app: FastAPI) -> None:
    """Un stack trace en la respuesta revela rutas, versiones y estructura interna.

    `raise_server_exceptions=False` hace que el cliente se comporte como un
    navegador real en vez de re-lanzar la excepcion dentro del test.
    """

    @api_app.get("/_test/boom")
    def _ruta() -> None:
        raise RuntimeError("la ruta secreta es /var/lib/firewall-dashboard/firewall.db")

    with TestClient(api_app, raise_server_exceptions=False) as cliente:
        respuesta = cliente.get("/_test/boom")

    assert respuesta.status_code == 500
    cuerpo = respuesta.json()
    _forma_de_error(cuerpo)
    assert cuerpo["error"]["code"] == "internal_error"
    assert "/var/lib" not in respuesta.text
    assert "RuntimeError" not in respuesta.text


class _CuerpoDePrueba(BaseModel):
    """A nivel de modulo a proposito, no dentro del test.

    Con `from __future__ import annotations` las anotaciones son cadenas, y
    FastAPI las resuelve contra los *globals* de la funcion. Un modelo definido
    dentro del test no esta en esos globals: la anotacion se queda en
    `ForwardRef`, FastAPI la toma por un escalar y el parametro pasa a ser de
    query en vez de body. El 422 llegaba igual, pero por el motivo equivocado.
    """

    puerto: int


def test_un_body_invalido_se_reempaqueta_como_los_demas(
    api_app: FastAPI, client: TestClient
) -> None:
    """Para el frontend, un 422 de Pydantic y uno del validador de reglas son lo mismo."""

    @api_app.post("/_test/echo")
    def _ruta(cuerpo: _CuerpoDePrueba) -> dict[str, int]:
        return {"puerto": cuerpo.puerto}

    respuesta = client.post("/_test/echo", json={"puerto": "no-es-un-numero"})
    assert respuesta.status_code == 422

    cuerpo = respuesta.json()
    _forma_de_error(cuerpo)
    assert cuerpo["error"]["code"] == "validation_error"
    assert cuerpo["error"]["details"]["errors"][0]["field"] == "puerto"
