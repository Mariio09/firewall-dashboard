"""Configuracion de la aplicacion via Pydantic Settings.

Bloque A1. Carga `.env`, valida tipos al arrancar y expone `get_settings()`
cacheado. Si falta una variable obligatoria, la app NO debe arrancar:
fallar en el arranque siempre es mejor que fallar en la primera peticion.

Variable clave: FIREWALL_BACKEND ('fake' | 'iptables'), el interruptor que
permite correr todo el bloque A en el Mac sin VM. Ver docs/ARCHITECTURE.md §4."""

from __future__ import annotations

import secrets
import warnings
from functools import lru_cache
from typing import Literal

from pydantic import Field, IPvAnyNetwork, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "get_settings"]

#: Entornos donde un secreto vacio es un error de despliegue, no una comodidad.
STRICT_ENVIRONMENTS: frozenset[str] = frozenset({"vm", "prod"})


class Settings(BaseSettings):
    """Configuracion completa del backend, validada en el arranque.

    Todos los campos se leen de variables de entorno o del archivo `.env`
    (mismos nombres, sin prefijo, sin distinguir mayusculas). La plantilla
    comentada esta en `backend/.env.example`.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Los valores por defecto tambien se validan: asi `management_allowed_cidr`
        # es una red de verdad incluso cuando nadie la define en el `.env`.
        validate_default=True,
        # Un `.env` puede traer variables de otras herramientas; no es motivo
        # para que la aplicacion se niegue a arrancar.
        extra="ignore",
    )

    # --- Aplicacion -------------------------------------------------------- #
    app_env: Literal["dev", "vm", "prod"] = "dev"
    app_name: str = "firewall-dashboard"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["console", "json"] = "console"

    # --- API --------------------------------------------------------------- #
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_v1_prefix: str = "/api/v1"
    # Lista separada por comas y NO una `list[str]` a proposito: pydantic-settings
    # intenta parsear los campos complejos como JSON, asi que un
    # `CORS_ORIGINS=http://localhost:5173` en el `.env` reventaria al arrancar.
    # Se expone ya troceada en la propiedad `cors_origin_list`.
    cors_origins: str = "http://localhost:5173"

    # --- Base de datos ------------------------------------------------------ #
    database_url: str = "sqlite:///./firewall.db"

    # --- Autenticacion (se consume en A4) ----------------------------------- #
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_expire_minutes: int = Field(default=30, ge=1)
    refresh_token_expire_days: int = Field(default=7, ge=1)
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: SecretStr = SecretStr("")

    # --- Firewall ----------------------------------------------------------- #
    firewall_backend: Literal["fake", "iptables"] = "fake"
    iptables_bin: str = "/usr/sbin/iptables"
    iptables_table: Literal["filter"] = "filter"
    managed_chain_prefix: str = Field(default="FWDASH", pattern=r"^[A-Z][A-Z0-9_]{1,20}$")
    use_sudo: bool = True
    command_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    auto_apply: bool = True

    # --- Proteccion contra auto-bloqueo ------------------------------------- #
    management_port: int = Field(default=8000, ge=1, le=65535)
    management_allowed_cidr: IPvAnyNetwork = Field(default="192.168.64.0/24")  # type: ignore[assignment]

    # ----------------------------------------------------------------------- #
    # Derivados
    # ----------------------------------------------------------------------- #

    @property
    def cors_origin_list(self) -> list[str]:
        """Origenes CORS ya troceados y sin espacios."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def is_strict_environment(self) -> bool:
        """`vm` y `prod` no perdonan configuracion a medias."""
        return self.app_env in STRICT_ENVIRONMENTS

    # ----------------------------------------------------------------------- #
    # Validaciones cruzadas: lo que un validador por campo no puede ver
    # ----------------------------------------------------------------------- #

    @model_validator(mode="after")
    def _validar_secreto_jwt(self) -> Settings:
        """Sin `JWT_SECRET_KEY` la aplicacion no arranca fuera de `dev`.

        En `dev` se genera uno efimero para no obligar a configurar nada antes
        del primer `make dev-backend`. El precio es explicito y se avisa: al
        reiniciar el proceso, todos los tokens emitidos dejan de valer.
        """
        if self.jwt_secret_key.get_secret_value():
            return self

        if self.is_strict_environment:
            raise ValueError(
                "JWT_SECRET_KEY es obligatoria con APP_ENV="
                f"{self.app_env}. Generala con: openssl rand -hex 32"
            )

        self.jwt_secret_key = SecretStr(secrets.token_hex(32))
        warnings.warn(
            "JWT_SECRET_KEY vacia: se ha generado una clave efimera para desarrollo. "
            "Los tokens emitidos dejaran de ser validos al reiniciar el proceso.",
            RuntimeWarning,
            stacklevel=2,
        )
        return self

    @model_validator(mode="after")
    def _validar_backend_de_firewall(self) -> Settings:
        """`fake` en produccion seria un firewall que no filtra nada."""
        if self.app_env == "prod" and self.firewall_backend == "fake":
            raise ValueError(
                "FIREWALL_BACKEND=fake con APP_ENV=prod: las reglas se guardarian "
                "en memoria y nunca llegarian a iptables."
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Instancia unica de la configuracion.

    Cacheada porque leer y validar el `.env` en cada peticion no aporta nada.
    En los tests, `get_settings.cache_clear()` fuerza la relectura.
    """
    return Settings()
