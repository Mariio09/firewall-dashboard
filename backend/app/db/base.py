"""DeclarativeBase de SQLAlchemy 2.0 y utilidades comunes a todos los modelos.

Bloque A1.

NOTA sobre el registro de modelos (cambio respecto al plan del scaffolding):
importar aqui los modelos, como decia el borrador, crea un ciclo real —
`db/base` importaria `models/rule`, que importa `db/base`, que aun no ha
terminado de ejecutarse—. El sintoma es un `ImportError: cannot import name
'Rule' from partially initialized module`, y aparece solo segun el orden en que
se importen los modulos, que es la peor clase de bug.

El registro vive por tanto en `app/models/__init__.py`, que importa todos los
modelos y no es importado por nadie de `db/`. Quien necesite el metadata
completo (Alembic) importa los dos:

    from app.db.base import Base
    import app.models  # noqa: F401  -> puebla Base.metadata

Sigue habiendo un unico sitio que añadir cuando aparezca un modelo nuevo; solo
que ese sitio es `models/__init__.py`."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = ["ADDRESS_LEN", "Base", "TimestampMixin", "str_enum", "utcnow"]

#: Longitud de una direccion IP en texto. 45 caracteres cubren el peor caso de
#: IPv6 con prefijo (`ffff:...:ffff/128`), asi que la columna sirve igual cuando
#: se implemente v6 sin necesidad de migrar.
ADDRESS_LEN = 45

#: Convencion de nombres para indices y constraints.
#:
#: No es cosmetica: SQLite no sabe hacer `ALTER TABLE DROP CONSTRAINT`, asi que
#: Alembic emula los cambios recreando la tabla (`render_as_batch=True`). Para
#: recrearla necesita poder NOMBRAR cada constraint, y una constraint anonima no
#: se puede nombrar. Sin esta convencion, la primera migracion que toque una
#: columna existente falla — y falla en la VM, no aqui.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    """Ahora, en UTC y con tzinfo.

    Todos los `datetime` de la base de datos son UTC (docs/ARCHITECTURE.md §5.1).
    La conversion a Europe/Madrid ocurre en el frontend, una sola vez, y no en
    cada consulta. `datetime.utcnow()` esta deprecada y ademas devuelve un
    datetime ingenuo, que es justo el bug que produce graficas desplazadas dos
    horas en verano.
    """
    return datetime.now(UTC)


def str_enum(enum_class: type[StrEnum], *, name: str) -> Enum:
    """Columna de texto respaldada por un `StrEnum`, con CHECK en la base de datos.

    Tres decisiones metidas en una funcion, para no repetirlas en cada modelo:

    - `native_enum=False`: SQLite no tiene tipo ENUM. Se guarda VARCHAR, que
      ademas es legible al abrir el `.db` con cualquier visor.
    - `create_constraint=True`: en SQLAlchemy 2.0 el CHECK **no** se crea por
      defecto. Sin el, la columna aceptaria cualquier cadena como accion y el
      error no aparecia hasta que el renderer intentara traducirla.
    - `values_callable`: guarda el VALOR del miembro (`"tcp"`), no su nombre
      (`"TCP"`). Es lo que espera iptables y lo que se ve en la API.

    Los enums de red no se redefinen aqui: son los de `app.firewall.spec`, unica
    fuente de verdad del dominio. La direccion de dependencia lo permite —
    `firewall/` sigue sin conocer el ORM, que es lo que verifica
    `tests/unit/test_architecture.py`.
    """
    return Enum(
        enum_class,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda enum: [member.value for member in enum],
    )


class Base(DeclarativeBase):
    """Base declarativa comun a todos los modelos."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TimestampMixin:
    """`created_at` / `updated_at` gestionados por la aplicacion.

    Se usan defaults de Python y no `func.now()` de SQL a proposito: SQLite
    guardaria la hora local del servidor sin zona horaria, y quedarse sin tzinfo
    es el origen de la mitad de los errores de fechas.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
