"""El backend de firewall es uno solo por aplicacion, y arranca con scaffold.

Con el fake, las cadenas viven en memoria. Si cada peticion construyera su propia
instancia, `POST /firewall/apply` escribiria en un objeto y `GET /firewall/status`
leeria otro recien nacido: el dashboard diria "sin aplicar" justo despues de
aplicar, y ninguno de los dos endpoints tendria la culpa a la vista.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.api.deps import build_firewall_backend, get_firewall_backend
from app.core.config import Settings
from app.core.exceptions import SecurityError
from app.firewall.iptables import IptablesBackend
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


# --------------------------------------------------------------------------- #
# El interruptor del ADR-0004, por el otro lado (B3)
# --------------------------------------------------------------------------- #

#: Ruta absoluta, con un nombre que SI esta en la allowlist, de algo que no
#: existe. Sirve para llegar hasta el subproceso sin depender de que la maquina
#: donde corre la suite tenga iptables — que es justo lo que no tiene el Mac.
IPTABLES_INEXISTENTE = "/nonexistent/sbin/iptables"


def _con_iptables(settings: Settings, **extra: object) -> Settings:
    return settings.model_copy(
        update={
            "firewall_backend": "iptables",
            "iptables_bin": IPTABLES_INEXISTENTE,
            "use_sudo": False,
            **extra,
        }
    )


def test_con_backend_iptables_se_construye_el_real(settings: Settings) -> None:
    """El bloque C es esta linea: cambiar una variable de entorno."""
    assert isinstance(build_firewall_backend(_con_iptables(settings)), IptablesBackend)


def test_un_iptables_bin_fuera_de_la_allowlist_no_llega_a_arrancar(settings: Settings) -> None:
    """El fallo de configuracion sale al construir, no en la primera peticion.

    Sin esta comprobacion la allowlist seria decoracion: el argv seguiria
    diciendo `iptables` y se ejecutaria `curl`.
    """
    with pytest.raises(SecurityError):
        build_firewall_backend(_con_iptables(settings, iptables_bin="/usr/bin/curl"))


def test_la_aplicacion_arranca_aunque_el_firewall_no_responda(settings: Settings) -> None:
    """Un dashboard de firewall que no arranca cuando el firewall falla no sirve.

    Es el caso real de la VM sin `CAP_NET_ADMIN` (ADR-0003). `/health` responde,
    `app.state.firewall` se queda sin poner, y la primera peticion a
    `/firewall/*` reintenta la construccion y devuelve el error de verdad.
    """
    app = create_app(_con_iptables(settings))
    with TestClient(app) as cliente:
        assert cliente.get("/api/v1/health").status_code == 200
    assert getattr(app.state, "firewall", None) is None
