"""El backend de firewall es uno solo por aplicacion, y arranca con scaffold.

Con el fake, las cadenas viven en memoria. Si cada peticion construyera su propia
instancia, `POST /firewall/apply` escribiria en un objeto y `GET /firewall/status`
leeria otro recien nacido: el dashboard diria "sin aplicar" justo despues de
aplicar, y ninguno de los dos endpoints tendria la culpa a la vista.
"""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.api.deps import get_firewall_backend
from app.core.config import Settings
from app.firewall.spec import Chain
from app.main import create_app


class _PeticionFalsa:
    """Lo unico que `get_firewall_backend` necesita de una peticion: la app."""

    def __init__(self, app: FastAPI) -> None:
        self.app = app


def _peticion(app: FastAPI) -> Request:
    return cast(Request, _PeticionFalsa(app))


def test_el_lifespan_deja_el_firewall_listo(client: TestClient, api_app: FastAPI) -> None:
    """Al arrancar, las cadenas gestionadas ya existen.

    Se comprueba leyendo: el fake imita a iptables tambien en el fallo, y leer
    una cadena inexistente lanzaria `FirewallCommandError`.
    """
    assert client.get("/api/v1/health").status_code == 200

    firewall: Any = api_app.state.firewall
    assert firewall is not None
    assert firewall.read_ruleset(Chain.INPUT) != []  # los guardianes ya estan


def test_todas_las_peticiones_comparten_el_mismo_backend(settings: Settings) -> None:
    """Dos resoluciones de la dependencia devuelven el MISMO objeto."""
    app = create_app(settings)
    peticion = _peticion(app)

    primero = get_firewall_backend(peticion, settings)
    segundo = get_firewall_backend(peticion, settings)

    assert primero is segundo


def test_aplicaciones_distintas_no_comparten_estado(settings: Settings) -> None:
    """El ambito es la aplicacion, no el proceso.

    Es la razon de guardarlo en `app.state` y no en una variable de modulo: cada
    test arranca con un firewall limpio sin tener que acordarse de vaciarlo.
    """
    primero = get_firewall_backend(_peticion(create_app(settings)), settings)
    segundo = get_firewall_backend(_peticion(create_app(settings)), settings)

    assert primero is not segundo


def test_el_fake_se_configura_con_los_settings(settings: Settings) -> None:
    """El puerto de gestion del `.env` tiene que llegar al argv del preview.

    Un fake que use sus valores por defecto mientras el real usa los del `.env`
    es la clase de mentira contra la que avisa docs/ARCHITECTURE.md §8: el
    preview enseñaria un comando distinto del que se acabaria ejecutando.
    """
    a_medida = settings.model_copy(
        update={"managed_chain_prefix": "OTRAAPP", "management_port": 8443}
    )
    backend = get_firewall_backend(_peticion(create_app(a_medida)), a_medida)

    resultado = backend.apply_ruleset(Chain.INPUT, [], dry_run=True)
    argv = [" ".join(comando) for comando in resultado.commands]

    assert any("OTRAAPP_INPUT" in linea for linea in argv)
    assert any("--dport 8443" in linea for linea in argv)
