"""Punto de entrada de la aplicacion FastAPI.

Se usa el patron de factoria (`create_app`) en lugar de una instancia global
porque permite construir una app limpia por test, con dependencias sobreescritas.

    uvicorn app.main:app --host 0.0.0.0 --port 8000

TODO(A1): registrar el router de la v1, los exception handlers de `api/errors.py`
y el middleware de request_id.
TODO(C2): en el evento de arranque, llamar a `ensure_scaffold()` y reconciliar la
politica desde la base de datos.
"""

from __future__ import annotations

from fastapi import FastAPI

__all__ = ["app", "create_app"]


def create_app() -> FastAPI:
    """Construye la aplicacion."""
    application = FastAPI(
        title="firewall-dashboard",
        description="Gestion de reglas de iptables con dashboard web.",
        version="0.0.1",
    )

    @application.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Liveness probe. Sin autenticacion, sin tocar la base de datos."""
        return {"status": "ok"}

    return application


app = create_app()
