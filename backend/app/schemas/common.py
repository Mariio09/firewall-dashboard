"""Schemas compartidos: Page[T] para paginacion y ErrorResponse.

Bloque A1. `ErrorResponse` es la forma unica de todos los errores de la API:
{"error": {"code", "message", "details", "request_id"}}. Ver §5.2."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ErrorBody",
    "ErrorResponse",
    "HealthResponse",
    "Page",
    "ReadinessResponse",
]

T = TypeVar("T")


class ErrorBody(BaseModel):
    """Contenido de un error. `details` es libre, pero siempre saneado."""

    code: str = Field(
        description="Identificador estable del error, apto para 'switch' en el front."
    )
    message: str = Field(description="Mensaje legible, en español, orientado a la persona.")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Contexto adicional. Nunca contiene stderr crudo ni rutas del sistema.",
    )
    request_id: str | None = Field(
        default=None,
        description="Identificador de la peticion. Es lo que se busca en los logs.",
    )


class ErrorResponse(BaseModel):
    """Envoltorio unico de TODOS los errores de la API.

    Que el frontend solo tenga que entender una forma de error es lo que permite
    tener un unico interceptor en `api/client.ts` en vez de un `if` por endpoint.
    """

    error: ErrorBody

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error": {
                    "code": "invalid_rule",
                    "message": "El puerto '99999' esta fuera del rango valido (1-65535).",
                    "details": {"field": "dst_port"},
                    "request_id": "01J8ZQ4T2N6R7V9WXYZ0ABCDEF",
                }
            }
        }
    )


class Page(BaseModel, Generic[T]):
    """Pagina de resultados.

    Se devuelve `total` ademas de los items porque la tabla del frontend
    necesita saber cuantas paginas hay antes de pintar el paginador.
    """

    items: list[T]
    total: int = Field(ge=0, description="Total de elementos que cumplen el filtro.")
    page: int = Field(default=1, ge=1)
    size: int = Field(default=50, ge=1, le=500)

    @property
    def pages(self) -> int:
        """Numero total de paginas, minimo 1."""
        if self.size <= 0:
            return 1
        return max(1, -(-self.total // self.size))


class HealthResponse(BaseModel):
    """Respuesta de `/health`. Deliberadamente minima: es un liveness probe."""

    status: str = "ok"


class ReadinessResponse(BaseModel):
    """Respuesta de `/ready`: si la aplicacion puede atender trabajo real.

    La diferencia con `/health` no es burocracia. `/health` dice "el proceso
    esta vivo"; `/ready` dice "sus dependencias responden". Un proceso vivo con
    la base de datos caida debe seguir contestando al primero y fallar el
    segundo, o el supervisor lo reiniciaria en bucle sin arreglar nada.
    """

    status: str = Field(description="'ready' o 'degraded'.")
    checks: dict[str, str] = Field(description="Resultado por dependencia.")
    firewall_backend: str = Field(description="Backend configurado: 'fake' o 'iptables'.")
