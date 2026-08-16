"""Fixtures compartidas.

Bloque A0: solo lo necesario para que la suite arranque. Las fixtures reales se
van añadiendo con cada paso.

TODO(A1): `db_session` — SQLite en memoria, rollback despues de cada test.
TODO(A3): `fake_firewall` — instancia limpia de FakeFirewallBackend.
TODO(A4): `auth_headers` — token valido de un usuario de prueba.
TODO(A5): `client` — TestClient con `dependency_overrides` inyectando las dos anteriores.
"""

from __future__ import annotations

from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
APP_ROOT = BACKEND_ROOT / "app"


@pytest.fixture(scope="session")
def backend_root() -> Path:
    """Raiz del paquete backend, para tests que inspeccionan el arbol de archivos."""
    return BACKEND_ROOT


@pytest.fixture(scope="session")
def app_root() -> Path:
    """Raiz del paquete `app`."""
    return APP_ROOT
