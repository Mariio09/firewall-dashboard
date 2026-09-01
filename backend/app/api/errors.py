"""Exception handlers: traducen la jerarquia `AppError` a JSON uniforme.

Bloque A1. El stderr crudo de iptables se loguea completo pero al cliente solo
va saneado: puede contener rutas y detalles de la topologia de red."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import AppError
from app.core.logging import get_logger

__all__ = ["register_exception_handlers"]

logger = get_logger(__name__)

#: Codigos legibles para los errores que no nacen de nuestra jerarquia (los que
#: lanza el propio Starlette: ruta inexistente, metodo no permitido...).
_CODIGOS_HTTP: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "too_many_requests",
    500: "internal_error",
    502: "firewall_error",
    503: "service_unavailable",
    504: "timeout",
}


def _envelope(
    *,
    code: str,
    message: str,
    request: Request,
    details: dict[str, Any] | None = None,
    status_code: int,
) -> JSONResponse:
    """Construye la unica forma de error que emite esta API."""
    request_id = getattr(request.state, "request_id", None)
    body = {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
            "request_id": request_id,
        }
    }
    headers = {"X-Request-ID": request_id} if request_id else None
    return JSONResponse(status_code=status_code, content=jsonable_encoder(body), headers=headers)


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Errores de dominio: ya saben su codigo y su status."""
    # Un 5xx es un fallo nuestro o del sistema y merece traza completa; un 4xx es
    # el usuario haciendo algo que no puede, y llenar el log de eso solo hace
    # ruido que tapa lo importante.
    if exc.http_status >= 500:
        logger.error(
            "error_de_dominio",
            code=exc.code,
            path=request.url.path,
            details=exc.details,
            exc_info=exc,
        )
    else:
        logger.info("peticion_rechazada", code=exc.code, path=request.url.path)

    return _envelope(
        code=exc.code,
        message=exc.message,
        details=exc.details,
        request=request,
        status_code=exc.http_status,
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Fallos de validacion de Pydantic en el borde HTTP.

    Se reempaquetan en el mismo sobre que el resto: para el frontend, un 422 de
    Pydantic y uno lanzado por `firewall/validators.py` deben ser el mismo caso.
    """
    errores = [
        {
            "field": ".".join(str(parte) for parte in error.get("loc", ()) if parte != "body"),
            "message": error.get("msg", ""),
            "type": error.get("type", ""),
        }
        for error in exc.errors()
    ]
    return _envelope(
        code="validation_error",
        message="Los datos enviados no son validos.",
        details={"errors": errores},
        request=request,
        status_code=422,
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """404, 405 y demas errores que genera el propio framework."""
    codigo = _CODIGOS_HTTP.get(exc.status_code, "http_error")
    mensaje = exc.detail if isinstance(exc.detail, str) else "Error en la peticion."
    return _envelope(code=codigo, message=mensaje, request=request, status_code=exc.status_code)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Ultima red: cualquier excepcion no prevista.

    El detalle real va integro al log —con traza y `request_id`— y al cliente le
    llega un mensaje generico. Un stack trace en la respuesta HTTP es una fuga
    de informacion gratuita: revela rutas, versiones y estructura interna.
    """
    logger.error(
        "excepcion_no_controlada",
        path=request.url.path,
        method=request.method,
        exc_info=exc,
    )
    return _envelope(
        code="internal_error",
        message="Ha ocurrido un error interno. Consulta el log con el request_id.",
        request=request,
        status_code=500,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Registra los cuatro handlers. Se llama desde `create_app`.

    Los `type: ignore` son inevitables: Starlette declara los handlers como
    `Callable[[Request, Exception], ...]`, pero cada uno de los nuestros recibe
    el tipo concreto con el que se registra. Tiparlos como `Exception` obligaria
    a un `isinstance` defensivo en cada handler que nunca podria fallar.
    """
    app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)
