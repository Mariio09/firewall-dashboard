"""La configuracion falla en el arranque, no en la primera peticion."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.core.config import Settings, get_settings


def test_valores_por_defecto_sirven_para_el_bloque_a() -> None:
    """Sin `.env`, la aplicacion arranca en modo Mac: fake y SQLite local."""
    settings = Settings(_env_file=None)
    assert settings.app_env == "dev"
    assert settings.firewall_backend == "fake"
    assert settings.is_sqlite


def test_cors_origins_se_trocea_por_comas() -> None:
    """El `.env` lleva una cadena; la aplicacion necesita una lista.

    El campo es `str` y no `list[str]` a proposito: pydantic-settings intenta
    parsear los campos complejos como JSON, y `CORS_ORIGINS=http://localhost:5173`
    reventaria al arrancar.
    """
    settings = Settings(
        _env_file=None,
        cors_origins="http://localhost:5173, http://192.168.64.5:5173 ,",
    )
    assert settings.cors_origin_list == [
        "http://localhost:5173",
        "http://192.168.64.5:5173",
    ]


@pytest.mark.parametrize("entorno", ["vm", "prod"])
def test_sin_secreto_jwt_no_arranca_fuera_de_dev(entorno: str) -> None:
    """Fallar al arrancar es mejor que emitir tokens firmados con una cadena vacia."""
    with pytest.raises(PydanticValidationError) as excinfo:
        Settings(_env_file=None, app_env=entorno, jwt_secret_key="", firewall_backend="iptables")
    assert "JWT_SECRET_KEY" in str(excinfo.value)


def test_en_dev_se_genera_un_secreto_efimero() -> None:
    """Comodidad en desarrollo, pero avisando: al reiniciar, los tokens mueren."""
    with pytest.warns(RuntimeWarning, match="efimera"):
        settings = Settings(_env_file=None, app_env="dev", jwt_secret_key="")
    assert len(settings.jwt_secret_key.get_secret_value()) == 64


def test_el_secreto_no_se_filtra_al_imprimir() -> None:
    """`SecretStr`: un `print(settings)` en caliente no debe volcar la clave."""
    settings = Settings(_env_file=None, jwt_secret_key="secreto-muy-largo-de-verdad")
    assert "secreto-muy-largo" not in repr(settings)
    assert "secreto-muy-largo" not in str(settings)


def test_backend_fake_prohibido_en_produccion() -> None:
    """Un firewall que guarda las reglas en memoria no filtra nada."""
    with pytest.raises(PydanticValidationError, match="fake"):
        Settings(_env_file=None, app_env="prod", jwt_secret_key="x" * 64, firewall_backend="fake")


@pytest.mark.parametrize(
    ("campo", "valor"),
    [
        ("firewall_backend", "nftables"),
        ("api_port", 70000),
        ("log_level", "CHATTY"),
        ("managed_chain_prefix", "fw-dash"),
        ("management_allowed_cidr", "192.168.64.0/99"),
        ("command_timeout_seconds", 0),
    ],
)
def test_valores_invalidos_se_rechazan(campo: str, valor: object) -> None:
    """Cada uno de estos, sin validar, acabaria en un comando o en una regla."""
    with pytest.raises(PydanticValidationError):
        Settings(_env_file=None, **{campo: valor})


def test_get_settings_esta_cacheado() -> None:
    """Leer y validar el `.env` en cada peticion no aporta nada."""
    assert get_settings() is get_settings()
