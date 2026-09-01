"""Engine, sessionmaker y la dependencia `get_session()`.

Bloque A1. Para SQLite hay que activar `PRAGMA foreign_keys=ON` en cada
conexion: SQLite no las aplica por defecto."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings

__all__ = [
    "create_db_engine",
    "get_engine",
    "get_session",
    "get_sessionmaker",
    "session_scope",
]


def _configurar_sqlite(dbapi_connection: Any, _connection_record: Any) -> None:
    """PRAGMAs que SQLite no aplica por su cuenta.

    - `foreign_keys=ON`: SQLite acepta claves foraneas en el esquema pero NO las
      hace cumplir salvo que se active por conexion. Sin esto, el
      `ON DELETE SET NULL` de `rules.created_by_id` seria decorativo.
    - `journal_mode=WAL`: permite leer mientras se escribe. Importa cuando en la
      fase 2 el worker de logs inserte mientras el dashboard consulta.
    - `busy_timeout`: espera en vez de devolver "database is locked" al instante.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


def create_db_engine(settings: Settings | None = None, **kwargs: Any) -> Engine:
    """Crea un engine ya configurado para el motor que toque."""
    settings = settings or get_settings()
    connect_args: dict[str, Any] = {}

    if settings.is_sqlite:
        # Uvicorn atiende las rutas sincronas en un threadpool, asi que la
        # conexion se usa desde hilos distintos al que la creo. La seguridad la
        # da el pool de SQLAlchemy, no esta comprobacion de SQLite.
        connect_args["check_same_thread"] = False

    engine = create_engine(
        settings.database_url,
        connect_args=connect_args,
        # `pool_pre_ping` detecta conexiones muertas antes de usarlas; con SQLite
        # es barato y evita sorpresas si algun dia se cambia de motor.
        pool_pre_ping=True,
        future=True,
        **kwargs,
    )

    if settings.is_sqlite:
        event.listen(engine, "connect", _configurar_sqlite)

    return engine


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Engine unico del proceso, creado de forma perezosa."""
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    """Fabrica de sesiones unica del proceso."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(),
            autocommit=False,
            autoflush=False,
            # Sin esto, leer un atributo de un objeto despues del commit dispara
            # un SELECT nuevo, y si la sesion ya esta cerrada, un DetachedInstanceError.
            expire_on_commit=False,
        )
    return _session_factory


def get_session() -> Generator[Session, None, None]:
    """Dependencia de FastAPI: una sesion por peticion.

    No hace `commit` por su cuenta. Quien decide cuando se confirma una
    transaccion es el servicio que conoce la operacion completa, no la capa de
    transporte.
    """
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Sesion transaccional para codigo que no vive en una peticion HTTP.

    Es lo que usan el `seed` del admin (A4) y el worker de logs (fase 2):
    confirma al salir bien, revierte si algo revienta.
    """
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
