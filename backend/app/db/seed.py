"""Creacion del usuario administrador inicial a partir de BOOTSTRAP_ADMIN_*.

Bloque A4. Idempotente: si el usuario ya existe, no hace nada.

Se ejecuta a mano —`make seed`, o `python -m app.db.seed`— y no en el arranque
de la aplicacion. Sembrar en el `lifespan` es comodo hasta el dia en que la app
arranca contra una base de datos sin migrar, o en el que un proceso reiniciado
en bucle crea usuarios; que la unica escritura fuera de una peticion HTTP sea un
comando explicito es mas facil de razonar y de auditar.
"""

from __future__ import annotations

import secrets
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.db.session import session_scope
from app.models.user import Role, User

__all__ = ["ensure_bootstrap_admin", "main"]

logger = get_logger(__name__)


def _resolver_password(settings: Settings) -> tuple[str, bool]:
    """La contraseña del admin inicial, y si ha habido que inventarsela.

    Nunca hay una contraseña por defecto en el codigo. Un `admin/admin` en un
    proyecto de seguridad es exactamente el hallazgo que este proyecto pretende
    saber encontrar, y ademas sobrevive a los despliegues: nadie cambia lo que
    ya funciona.

    Fuera de `dev`, faltar `BOOTSTRAP_ADMIN_PASSWORD` es un error de despliegue
    y el comando falla. En `dev` se genera una aleatoria y se imprime una sola
    vez, que es comodo sin ser inseguro.
    """
    configurada = settings.bootstrap_admin_password.get_secret_value()
    if configurada:
        return configurada, False

    if settings.is_strict_environment:
        raise RuntimeError(
            "BOOTSTRAP_ADMIN_PASSWORD es obligatoria con APP_ENV="
            f"{settings.app_env}. Generala con: openssl rand -base64 24"
        )

    return secrets.token_urlsafe(18), True


def ensure_bootstrap_admin(session: Session, settings: Settings | None = None) -> User | None:
    """Crea el administrador inicial si no existe. Devuelve `None` si ya estaba.

    La idempotencia se comprueba por nombre de usuario y no por "¿hay algun
    usuario?": si alguien borra al admin por error, volver a ejecutar esto lo
    recupera sin tocar al resto de cuentas.

    No confirma la transaccion; eso es cosa de quien abre la sesion (`main` usa
    `session_scope`, que confirma al salir).
    """
    settings = settings or get_settings()
    nombre = settings.bootstrap_admin_username.strip()

    existente = session.execute(select(User).where(User.username == nombre)).scalar_one_or_none()
    if existente is not None:
        logger.info("seed_admin_omitido", username=nombre, motivo="ya_existe")
        return None

    password, generada = _resolver_password(settings)
    admin = User(
        username=nombre,
        hashed_password=hash_password(password),
        role=Role.ADMIN,
        is_active=True,
    )
    session.add(admin)
    session.flush()

    logger.info("seed_admin_creado", username=nombre, password_generada=generada)
    if generada:
        # A stdout y no al log: el log puede ir a un archivo o en JSON, y esto
        # tiene que verlo la persona que acaba de lanzar el comando. Se enseña
        # una vez; no se guarda en ninguna parte.
        print(
            f"\n  Administrador creado: {nombre}"
            f"\n  Contraseña generada:  {password}"
            "\n  Apuntala ahora: no se vuelve a mostrar y no se puede recuperar.\n"
        )
    return admin


def main() -> int:
    """Punto de entrada de `make seed` / `python -m app.db.seed`."""
    settings = get_settings()
    configure_logging(settings)
    with session_scope() as session:
        creado = ensure_bootstrap_admin(session, settings)
    if creado is None:
        print(f"El usuario '{settings.bootstrap_admin_username}' ya existe: no se ha creado nada.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
