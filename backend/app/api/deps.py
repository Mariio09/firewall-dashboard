"""Dependencias compartidas de FastAPI.

Bloque A1+. Aqui vive `get_firewall_backend()`, que devuelve `FakeFirewallBackend`
o `IptablesBackend` segun `settings.firewall_backend`. Esa unica funcion es lo que
permite correr el MVP completo en el Mac y lo que hace el bloque C casi trivial."""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.firewall.base import FirewallBackend
from app.firewall.fake import FakeFirewallBackend

__all__ = [
    "CurrentSettings",
    "DbSession",
    "Firewall",
    "get_db",
    "get_firewall_backend",
    "get_request_id",
]


def get_db() -> Generator[Session, None, None]:
    """Una sesion de base de datos por peticion."""
    yield from get_session()


def get_settings_dep() -> Settings:
    """La configuracion, como dependencia inyectable.

    Pedirla por inyeccion en vez de llamar a `get_settings()` dentro del handler
    permite sobreescribirla en los tests con `dependency_overrides`.
    """
    return get_settings()


def get_request_id(request: Request) -> str | None:
    """Identificador de la peticion actual, puesto por el middleware."""
    return getattr(request.state, "request_id", None)


def get_firewall_backend(
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> FirewallBackend:
    """Devuelve el backend de firewall configurado.

    Estas seis lineas son la costura entera del proyecto (ADR-0004): con
    `FIREWALL_BACKEND=fake` la aplicacion funciona de punta a punta en el Mac,
    sin VM y sin privilegios, y el bloque C consiste en cambiar esa variable.

    `IptablesBackend` necesita un `CommandRunner` real, que es el bloque B2. Se
    construye ahi, no aqui, para no arrastrar `subprocess` a un import que
    ocurre tambien en el Mac.
    """
    if settings.firewall_backend == "fake":
        return FakeFirewallBackend()

    # TODO(B2/B3): construir SubprocessRunner + IptablesBackend con los valores
    # de `settings` (iptables_bin, use_sudo, timeout, prefijo de cadena y los
    # parametros de las reglas guardian).
    raise NotImplementedError(
        "El backend 'iptables' se implementa en el bloque B. "
        "Usa FIREWALL_BACKEND=fake mientras tanto."
    )


DbSession = Annotated[Session, Depends(get_db)]
CurrentSettings = Annotated[Settings, Depends(get_settings_dep)]
Firewall = Annotated[FirewallBackend, Depends(get_firewall_backend)]
