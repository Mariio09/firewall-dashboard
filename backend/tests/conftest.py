"""Fixtures compartidas.

Estado tras A1: configuracion de prueba, base de datos en memoria y cliente HTTP.

Estado tras A3: `fake_firewall`, con las cadenas gestionadas ya creadas.

Estado tras A4: `crear_usuario`, `admin_user`, `operator_user`, `viewer_user`,
`headers_de` y `auth_headers` (el admin, que es el caso comun).

Estado tras A5: `crear_regla`, que da de alta reglas por la API.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db, get_settings_dep
from app.core.config import Settings, get_settings
from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.session import create_db_engine
from app.firewall.fake import FakeFirewallBackend
from app.main import create_app
from app.models.user import Role, User

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
    # Tambien la configuracion: `get_settings_dep` leeria el `.env` de la
    # maquina, y entonces la aplicacion firmaria los tokens con una clave y los
    # tests los verificarian con otra. Sin esto, un fallo de auth en los tests
    # puede venir de un archivo que ni siquiera esta en el repositorio.
    application.dependency_overrides[get_settings_dep] = lambda: settings
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


# --------------------------------------------------------------------------- #
# Usuarios y tokens (A4)
# --------------------------------------------------------------------------- #

#: La contraseña de todos los usuarios de prueba. Constante y visible: es un
#: valor de test, y esconderlo solo dificultaria leer los fallos.
#:
#: `gitleaks:allow` porque el detector la marca por entropia (3.91) sin poder
#: saber que no vale para nada. La marca va en ESTA linea y solo en esta: si
#: alguien pusiera aqui un secreto de verdad, gitleaks tampoco lo vería — es el
#: precio de silenciar un falso positivo, y por eso se silencia una linea y no
#: el archivo ni la carpeta de tests.
PASSWORD_DE_PRUEBA = "contrasena-de-prueba-1234"  # gitleaks:allow


@pytest.fixture
def crear_usuario(db_session: Session) -> Callable[..., User]:
    """Fabrica usuarios ya guardados. El rol y el estado son lo que se varia.

    Se devuelve una fabrica y no un usuario porque la mayoria de los tests de
    permisos necesitan dos o tres cuentas distintas en el mismo test.
    """

    def _crear(
        username: str = "prueba",
        *,
        role: Role = Role.VIEWER,
        password: str = PASSWORD_DE_PRUEBA,
        is_active: bool = True,
        email: str | None = None,
    ) -> User:
        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role=role,
            is_active=is_active,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return _crear


@pytest.fixture
def admin_user(crear_usuario: Callable[..., User]) -> User:
    return crear_usuario("admin", role=Role.ADMIN)


@pytest.fixture
def operator_user(crear_usuario: Callable[..., User]) -> User:
    return crear_usuario("operador", role=Role.OPERATOR)


@pytest.fixture
def viewer_user(crear_usuario: Callable[..., User]) -> User:
    return crear_usuario("observador", role=Role.VIEWER)


@pytest.fixture
def headers_de(settings: Settings) -> Callable[[User], dict[str, str]]:
    """Cabecera `Authorization` con un access token recien firmado para ese usuario.

    Firma el token directamente en vez de pasar por `/auth/login`: un test de
    reglas no deberia fallar porque se haya roto el login, y ademas se ahorra
    un hash de Argon2 por test.
    """

    def _headers(user: User) -> dict[str, str]:
        token = create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role.value,
            settings=settings,
        )
        return {"Authorization": f"Bearer {token}"}

    return _headers


@pytest.fixture
def auth_headers(admin_user: User, headers_de: Callable[[User], dict[str, str]]) -> dict[str, str]:
    """El caso comun: cabeceras de un administrador."""
    return headers_de(admin_user)


# --------------------------------------------------------------------------- #
# Reglas (A5)
# --------------------------------------------------------------------------- #

#: Lo minimo que acepta `POST /rules`. Todo lo demas se pasa como `extra`.
REGLA_MINIMA: dict[str, object] = {"name": "regla de prueba", "chain": "INPUT", "action": "DROP"}


@pytest.fixture
def crear_regla(client: TestClient, auth_headers: dict[str, str]) -> Callable[..., dict[str, Any]]:
    """Da de alta una regla POR LA API y devuelve el cuerpo de la respuesta.

    Por la API y no insertando la fila a mano: asi las reglas de los tests pasan
    por la misma normalizacion y las mismas posiciones que las de verdad. Una
    fixture que inserte `Rule(...)` directamente acaba creando estados que la
    aplicacion no puede producir, y entonces los tests dejan de decir nada.
    """

    def _crear(**extra: Any) -> dict[str, Any]:
        respuesta = client.post("/api/v1/rules", json=REGLA_MINIMA | extra, headers=auth_headers)
        assert respuesta.status_code == 201, respuesta.text
        cuerpo: dict[str, Any] = respuesta.json()
        return cuerpo

    return _crear
