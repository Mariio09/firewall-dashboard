"""Comprobaciones minimas de que el esqueleto se sostiene."""

from __future__ import annotations

import importlib
import pkgutil

import pytest
from fastapi.testclient import TestClient

import app as app_package
from app.firewall.base import FirewallBackend
from app.firewall.fake import FakeFirewallBackend
from app.firewall.iptables import IptablesBackend
from app.firewall.spec import Action, Chain, Protocol, RuleSpec, SyncState
from app.main import create_app


def test_todos_los_modulos_importan() -> None:
    """Ningun modulo del paquete tiene errores de sintaxis o imports rotos."""
    fallos: list[str] = []
    for info in pkgutil.walk_packages(app_package.__path__, prefix="app."):
        try:
            importlib.import_module(info.name)
        except Exception as exc:
            fallos.append(f"{info.name}: {exc}")
    assert not fallos, "Modulos que no importan:\n" + "\n".join(fallos)


def test_health_responde() -> None:
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_los_dos_backends_cumplen_el_mismo_contrato() -> None:
    """La costura del §3.4: fake e iptables son intercambiables.

    Si esta comprobacion falla, el bloque C (interconexion) deja de ser un cambio
    de variable de entorno.
    """
    assert isinstance(FakeFirewallBackend(), FirewallBackend)
    assert isinstance(IptablesBackend(runner=None), FirewallBackend)  # type: ignore[arg-type]


def test_se_gestionan_las_tres_cadenas() -> None:
    """Decision confirmada: INPUT, OUTPUT y FORWARD."""
    assert {c.value for c in Chain} == {"INPUT", "OUTPUT", "FORWARD"}


def test_log_no_es_una_accion_de_usuario() -> None:
    """LOG no se elige: lo emite el renderer cuando `log_enabled` esta activo."""
    assert "LOG" not in {a.value for a in Action}


def test_estados_de_sincronizacion() -> None:
    assert {s.value for s in SyncState} == {"pending", "applied", "failed", "drift"}


def test_rulespec_es_inmutable() -> None:
    """Una spec no puede mutarse despues de validada."""
    spec = RuleSpec(chain=Chain.INPUT, action=Action.DROP, protocol=Protocol.TCP)
    with pytest.raises((AttributeError, TypeError)):
        spec.action = Action.ACCEPT  # type: ignore[misc]
