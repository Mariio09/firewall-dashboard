"""Fixtures compartidas.

Estado tras A1: configuracion de prueba, base de datos en memoria y cliente HTTP.

Estado tras A3: `fake_firewall`, con las cadenas gestionadas ya creadas.
TODO(A4): `auth_headers` — token valido de un usuario de prueba.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.session import create_db_engine
from app.firewall.fake import FakeFirewallBackend
from app.main import create_app

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


@pytest.fixture
def settings() -> Settings:
    """Configuracion de prueba, independiente del `.env` que haya en la maquina.

    Los valores se pasan explicitos precisamente para que un `.env` local no
    pueda cambiar el resultado de la suite: un test que pasa en tu Mac y falla
    en CI por una variable de entorno es tiempo perdido garantizado.
    """
    return Settings(
        app_env="dev",
        database_url="sqlite://",  # en memoria
        jwt_secret_key="clave-de-prueba-no-usar-fuera-de-los-tests",
        firewall_backend="fake",
        log_format="console",
        log_level="WARNING",
        cors_origins="http://localhost:5173",
    )


@pytest.fixture
def engine(settings: Settings) -> Iterator[Engine]:
    """Engine SQLite en memoria con el esquema ya creado.

    `StaticPool` mantiene UNA sola conexion: en SQLite, cada conexion nueva a
    `:memory:` es una base de datos distinta y vacia, asi que sin esto el test
    crearia las tablas en una base y consultaria otra.

    El esquema se crea con `create_all`, no con Alembic, porque es mucho mas
    rapido. Que ambos caminos produzcan el mismo esquema lo verifica
    `tests/integration/test_migrations.py`, que es donde debe verificarse.
    """
    engine = create_db_engine(settings, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    """Una sesion por test, sobre la base en memoria."""
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def api_app(settings: Settings, db_session: Session) -> FastAPI:
    """Aplicacion FastAPI con la base de datos de prueba inyectada."""
    application = create_app(settings)

    def _override_get_db() -> Iterator[Session]:
        yield db_session

    application.dependency_overrides[get_db] = _override_get_db
    return application


@pytest.fixture
def client(api_app: FastAPI) -> Iterator[TestClient]:
    """Cliente HTTP contra la aplicacion de prueba.

    Se usa como context manager para que se ejecute el `lifespan`: si algun dia
    el arranque falla (por ejemplo al añadir `ensure_scaffold` en C2), los tests
    deben enterarse.
    """
    with TestClient(api_app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _limpiar_cache_de_settings() -> Iterator[None]:
    """La configuracion esta cacheada; entre tests hay que soltarla.

    Sin esto, el primer test que llame a `get_settings()` fija la configuracion
    para toda la sesion de pytest y los tests siguientes que toquen variables de
    entorno no verian ningun cambio.
    """
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def fake_firewall() -> FakeFirewallBackend:
    """Backend de firewall en memoria, con las cadenas gestionadas ya creadas.

    Se devuelve ya "scaffoldeado" porque es el estado en el que la aplicacion lo
    encuentra siempre: `ensure_scaffold()` corre en el arranque. Un test que
    quiera probar el caso contrario construye el suyo.
    """
    backend = FakeFirewallBackend()
    backend.ensure_scaffold()
    return backend
