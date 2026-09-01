"""La migracion tiene que producir exactamente el esquema de los modelos.

Este es el test que justifica escribir la migracion inicial a mano. El riesgo de
una migracion manual es que se desvie de los modelos sin que nadie lo note: la
suite pasaria (usa `create_all`) y la VM tendria otro esquema (usa Alembic). Aqui
se comparan los dos caminos.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect

import app.models  # noqa: F401  -> puebla Base.metadata
from alembic import command
from app.core.config import get_settings
from app.db.base import Base

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def esquema_migrado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Aplica `alembic upgrade head` sobre una SQLite vacia y devuelve su esquema."""
    db_path = tmp_path / "migrada.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("APP_ENV", "dev")
    get_settings.cache_clear()

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{db_path}")
    inspector = inspect(engine)
    esquema = {
        "tablas": {nombre for nombre in inspector.get_table_names() if nombre != "alembic_version"},
        "columnas": {
            tabla: {columna["name"] for columna in inspector.get_columns(tabla)}
            for tabla in inspector.get_table_names()
            if tabla != "alembic_version"
        },
        "indices": {
            tabla: {indice["name"] for indice in inspector.get_indexes(tabla)}
            for tabla in inspector.get_table_names()
            if tabla != "alembic_version"
        },
    }
    engine.dispose()
    return esquema


def test_la_migracion_crea_las_mismas_tablas(esquema_migrado: dict) -> None:
    assert esquema_migrado["tablas"] == set(Base.metadata.tables)


def test_la_migracion_crea_las_mismas_columnas(esquema_migrado: dict) -> None:
    """Una columna olvidada aqui es un `OperationalError` en la VM, no antes."""
    for nombre, tabla in Base.metadata.tables.items():
        esperadas = {columna.name for columna in tabla.columns}
        assert esquema_migrado["columnas"][nombre] == esperadas, f"tabla {nombre}"


def test_la_migracion_crea_los_mismos_indices(esquema_migrado: dict) -> None:
    """Sin indices la aplicacion funciona igual... hasta que la tabla crece.

    Es justo el tipo de diferencia que no da error y solo se nota en la fase 3,
    cuando las graficas tardan segundos en cargar.
    """
    for nombre, tabla in Base.metadata.tables.items():
        esperados = {indice.name for indice in tabla.indexes}
        # Los indices unicos derivados de una UniqueConstraint los crea SQLite
        # con un nombre automatico (`sqlite_autoindex_*`), asi que se ignoran.
        obtenidos = {
            indice
            for indice in esquema_migrado["indices"][nombre]
            if indice and not indice.startswith("sqlite_autoindex")
        }
        assert obtenidos == esperados, f"tabla {nombre}"


def test_la_migracion_se_puede_deshacer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Un `downgrade` que no funciona es una migracion sin marcha atras.

    Importa mas de lo que parece: es el unico camino de vuelta si una migracion
    futura sale mal en la VM.
    """
    db_path = tmp_path / "ida-y-vuelta.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    get_settings.cache_clear()

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = create_engine(f"sqlite:///{db_path}")
    restantes = {tabla for tabla in inspect(engine).get_table_names() if tabla != "alembic_version"}
    engine.dispose()
    assert restantes == set()
