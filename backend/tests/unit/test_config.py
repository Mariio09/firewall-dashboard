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


@pytest.mark.parametrize(
    ("entorno", "backend"),
    [("vm", "iptables"), ("prod", "iptables"), ("dev", "iptables"), ("vm", "fake")],
)
def test_sin_cidr_de_gestion_no_arranca_cuando_las_reglas_son_reales(
    entorno: str, backend: str
) -> None:
    """ADR-0016: la red desde la que se administra se declara, no se supone.

    `dev` con el backend real entra tambien: lo que hace peligroso el hueco no es
    el nombre del entorno, es que las reglas lleguen a iptables.
    """
    with pytest.raises(PydanticValidationError) as excinfo:
        Settings(
            _env_file=None,
            app_env=entorno,
            jwt_secret_key="x" * 64,
            firewall_backend=backend,
            management_allowed_cidr=None,
        )
    assert "MANAGEMENT_ALLOWED_CIDR" in str(excinfo.value)


def test_con_backend_fake_el_cidr_es_de_laboratorio_y_se_avisa() -> None:
    """Contraprueba del test anterior: sin reglas reales SI se arranca.

    Y lo que se rellena no es una red plausible, que es lo que se acaba de
    prohibir, sino una que nadie puede confundir con la suya.
    """
    with pytest.warns(RuntimeWarning, match="MANAGEMENT_ALLOWED_CIDR"):
        settings = Settings(_env_file=None, app_env="dev", firewall_backend="fake")
    assert str(settings.management_allowed_cidr) == "127.0.0.0/8"


def test_el_default_que_provocaba_el_auto_bloqueo_ya_no_existe() -> None:
    """La regresion concreta que cierra el ADR-0016.

    `192.168.64.0/24` era el rango HABITUAL del bridge de Multipass en macOS, no
    uno garantizado: en el Mac donde se desarrolla esto la red real es otra. Un
    default que casi siempre acierta es peor que ninguno cuando lo que esta en
    juego es el acceso a la maquina.
    """
    campo = Settings.model_fields["management_allowed_cidr"]
    assert campo.default is None
    assert "192.168.64.0/24" not in str(campo)


def test_get_settings_esta_cacheado() -> None:
    """Leer y validar el `.env` en cada peticion no aporta nada."""
    assert get_settings() is get_settings()
