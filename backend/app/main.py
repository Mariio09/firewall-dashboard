"""Punto de entrada de la aplicacion FastAPI.

Se usa el patron de factoria (`create_app`) en lugar de una instancia global
porque permite construir una app limpia por test, con dependencias sobreescritas.

    uvicorn app.main:app --host 0.0.0.0 --port 8000

TODO(C2): en el evento de arranque, llamar a `ensure_scaffold()` y reconciliar la
politica desde la base de datos.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import RequestResponseEndpoint

from app.api.errors import register_exception_handlers
from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.logging import (
    bind_request_context,
    clear_request_context,
    configure_logging,
    get_logger,
    new_request_id,
)

__all__ = ["app", "create_app"]

logger = get_logger(__name__)

#: Cabecera estandar de facto para propagar el identificador de peticion.
REQUEST_ID_HEADER = "X-Request-ID"


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Arranque y parada de la aplicacion."""
    settings: Settings = application.state.settings
    logger.info(
        "aplicacion_iniciada",
        app_env=settings.app_env,
        firewall_backend=settings.firewall_backend,
        # La URL de la base de datos puede llevar credenciales cuando no sea
        # SQLite; se registra solo el motor.
        db_engine=settings.database_url.split("://", 1)[0],
    )
    # TODO(C2): backend.ensure_scaffold() y reconciliacion desde la DB.
    yield
    logger.info("aplicacion_detenida")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Construye la aplicacion."""
    settings = settings or get_settings()
    configure_logging(settings)

    application = FastAPI(
        title="firewall-dashboard",
        description="Gestion de reglas de iptables con dashboard web.",
        version="0.0.1",
        lifespan=lifespan,
    )
    application.state.settings = settings

    # --- Middlewares ------------------------------------------------------- #
    # Se registran antes que las rutas por claridad; el orden de ejecucion en
    # Starlette es inverso al de registro (el ultimo registrado es el mas
    # externo), asi que el de request_id envuelve al de CORS y todo log emitido
    # durante la peticion lleva el identificador.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[REQUEST_ID_HEADER],
    )

    @application.middleware("http")
    async def request_context_middleware(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Ata un `request_id` a la peticion y a todo lo que se loguee en ella.

        Si el cliente ya envia uno, se respeta: eso permite seguir una peticion
        desde el navegador hasta el log del backend sin correlacionar a ojo.
        """
        request_id = request.headers.get(REQUEST_ID_HEADER) or new_request_id()
        request.state.request_id = request_id
        bind_request_context(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        try:
            response = await call_next(request)
        finally:
            # Imprescindible: los contextvars viven en el hilo/tarea, que se
            # reutiliza. Sin limpiar, la siguiente peticion heredaria el
            # request_id de la anterior y el log mentiria.
            clear_request_context()
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    # --- Errores ----------------------------------------------------------- #
    register_exception_handlers(application)

    # --- Rutas ------------------------------------------------------------- #
    application.include_router(api_router, prefix=settings.api_v1_prefix)
    # `/health` y `/ready` se exponen ademas en la raiz, sin prefijo de version:
    # una sonda de supervision no deberia tener que saber en que version de la
    # API va la aplicacion.
    application.include_router(health_router, include_in_schema=False)

    return application


app = create_app()
