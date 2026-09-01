"""Entorno de Alembic.

La URL de la base de datos se toma de `app.core.config`, no de `alembic.ini`: asi
existe una unica fuente de configuracion y no hay que mantener la cadena de
conexion en dos sitios.

`render_as_batch=True` no es opcional con SQLite: no soporta `ALTER TABLE` completo,
asi que Alembic recrea la tabla para cualquier cambio de columna o constraint. Sin
ese flag, la primera migracion que modifique algo existente falla.
"""

from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# `alembic` se invoca desde `backend/`, pero no necesariamente con esa ruta en
# el PYTHONPATH (por ejemplo al lanzarlo desde la raiz del repo o desde la VM).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401  -> importar los modelos puebla Base.metadata
from app.core.config import get_settings
from app.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Genera SQL sin conectarse a la base de datos."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        # Sin esto, autogenerate ignora los cambios de tipo de una columna.
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Aplica las migraciones contra una conexion real."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # imprescindible en SQLite
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
