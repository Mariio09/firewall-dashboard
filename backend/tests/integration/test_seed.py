"""`db/seed.py`: el administrador inicial.

Lo importante que se comprueba aqui: que es idempotente, que nunca hay una
contraseña por defecto en el codigo, y que fuera de `dev` faltar
`BOOTSTRAP_ADMIN_PASSWORD` es un error de despliegue y no un aviso.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import verify_password
from app.db.seed import ensure_bootstrap_admin
from app.models.user import Role, User

PASSWORD = "una-contrasena-de-bootstrap"


def _settings(**cambios: object) -> Settings:
    """Configuracion de prueba que NO lee el `.env` de la maquina.

    `_env_file=None` no es cosmetico: sin el, estos tests pasaban en el host —donde
    `backend/.env` existe y trae `MANAGEMENT_ALLOWED_CIDR`— y fallaban dentro de la
    VM, donde el clon no tiene `.env`: con `app_env="vm"` saltaba el validador del
    ADR-0016 y el test recibia un `ValidationError` en vez del `RuntimeError` que
    esperaba. Es la trampa de A4 otra vez, y por eso el CIDR va explicito: un test
    que depende de un archivo que ni siquiera esta en el repositorio no prueba lo
    que dice probar.
    """
    base: dict[str, object] = {
        "_env_file": None,
        "app_env": "dev",
        "database_url": "sqlite://",
        "jwt_secret_key": "clave-de-prueba-no-usar-fuera-de-los-tests",
        "firewall_backend": "fake",
        "management_allowed_cidr": "192.168.64.0/24",
        "bootstrap_admin_username": "admin",
        "bootstrap_admin_password": PASSWORD,
    }
    base.update(cambios)
    return Settings(**base)  # type: ignore[arg-type]


def _cuantos(session: Session) -> int:
    return session.execute(select(func.count()).select_from(User)).scalar_one()


def test_crea_el_admin_con_la_contrasena_configurada(db_session: Session) -> None:
    admin = ensure_bootstrap_admin(db_session, _settings())
    db_session.commit()

    assert admin is not None
    assert admin.username == "admin"
    assert admin.role is Role.ADMIN
    assert admin.is_active is True
    assert verify_password(PASSWORD, admin.hashed_password)


def test_ejecutarlo_dos_veces_no_crea_un_segundo_admin(db_session: Session) -> None:
    ensure_bootstrap_admin(db_session, _settings())
    db_session.commit()

    assert ensure_bootstrap_admin(db_session, _settings()) is None
    assert _cuantos(db_session) == 1


def test_no_toca_a_un_admin_que_ya_existe(
    db_session: Session, crear_usuario: Callable[..., User]
) -> None:
    """Volver a sembrar no puede reescribir la contraseña de nadie."""
    existente = crear_usuario("admin", role=Role.ADMIN)
    hash_original = existente.hashed_password

    ensure_bootstrap_admin(db_session, _settings())
    db_session.commit()
    db_session.refresh(existente)

    assert existente.hashed_password == hash_original


def test_respeta_el_nombre_configurado(db_session: Session) -> None:
    admin = ensure_bootstrap_admin(db_session, _settings(bootstrap_admin_username="mario"))
    db_session.commit()

    assert admin is not None
    assert admin.username == "mario"


def test_sin_contrasena_en_dev_se_genera_y_se_enseña_una_vez(
    db_session: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    admin = ensure_bootstrap_admin(db_session, _settings(bootstrap_admin_password=""))
    db_session.commit()

    assert admin is not None
    salida = capsys.readouterr().out
    assert "Contraseña generada" in salida
    # La que se imprime es la que sirve para entrar: si no, el mensaje seria una
    # trampa que se descubre en el primer login.
    generada = salida.split("Contraseña generada:")[1].split("\n")[0].strip()
    assert verify_password(generada, admin.hashed_password)


def test_sin_contrasena_fuera_de_dev_es_un_error(db_session: Session) -> None:
    """En la VM, un admin con contraseña inventada por la maquina es peor que un fallo."""
    with pytest.raises(RuntimeError, match="BOOTSTRAP_ADMIN_PASSWORD"):
        ensure_bootstrap_admin(db_session, _settings(app_env="vm", bootstrap_admin_password=""))

    assert _cuantos(db_session) == 0
