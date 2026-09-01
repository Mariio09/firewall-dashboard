"""Jerarquia de excepciones de dominio.

Bloque A1. Los servicios lanzan estas, NUNCA `HTTPException`: eso los ataria a
FastAPI y romperia los tests unitarios. La traduccion a HTTP ocurre en
`app/api/errors.py`. Ver docs/ARCHITECTURE.md §5.2."""

from __future__ import annotations

from typing import Any

__all__ = [
    "AppError",
    "AuthError",
    "ConflictError",
    "FirewallCommandError",
    "FirewallDriftError",
    "FirewallError",
    "FirewallTimeoutError",
    "ForbiddenError",
    "InvalidRuleError",
    "NotFoundError",
    "SecurityError",
    "ValidationError",
]


class AppError(Exception):
    """Raiz de todos los errores de dominio.

    Tres atributos de clase definen como se traduce a HTTP; las subclases solo
    los sobreescriben. `details` es un diccionario libre que llega al cliente
    tal cual, asi que **nunca** debe contener stderr crudo, rutas del sistema ni
    secretos: eso va al log, no a la respuesta.
    """

    code: str = "internal_error"
    http_status: int = 500
    message: str = "Ha ocurrido un error interno."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        self.message = message or type(self).message
        self.details: dict[str, Any] = details or {}
        if code is not None:
            self.code = code
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Cuerpo del error, sin `request_id`: lo añade el handler HTTP."""
        return {"code": self.code, "message": self.message, "details": self.details}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# --------------------------------------------------------------------------- #
# Entrada del usuario
# --------------------------------------------------------------------------- #


class ValidationError(AppError):
    """Datos sintacticamente correctos pero semanticamente invalidos."""

    code = "validation_error"
    http_status = 422
    message = "Los datos enviados no son validos."


class InvalidRuleError(ValidationError):
    """Una regla que iptables rechazaria, o que no tiene sentido de red.

    La lanza `firewall/validators.py`, que es el unico modulo con permiso para
    interpretar una IP, un puerto o un nombre de interfaz.
    """

    code = "invalid_rule"
    message = "La regla no es valida."


class NotFoundError(AppError):
    code = "not_found"
    http_status = 404
    message = "El recurso solicitado no existe."


class ConflictError(AppError):
    """Choque con el estado actual: posicion ocupada, nombre duplicado."""

    code = "conflict"
    http_status = 409
    message = "La operacion entra en conflicto con el estado actual."


# --------------------------------------------------------------------------- #
# Identidad y permisos
# --------------------------------------------------------------------------- #


class AuthError(AppError):
    """No sabemos quien eres: falta el token, esta caducado o es invalido."""

    code = "unauthorized"
    http_status = 401
    message = "Credenciales invalidas o ausentes."


class ForbiddenError(AppError):
    """Sabemos quien eres y no te alcanza el rol.

    Se llama `ForbiddenError` y no `PermissionError` (como decia el borrador de
    la arquitectura) para no ensombrecer el builtin de Python, que es un
    `OSError` y aparece de verdad al tocar el sistema de archivos. Confundir los
    dos en un `except` seria un fallo silencioso.
    """

    code = "forbidden"
    http_status = 403
    message = "No tienes permisos para realizar esta operacion."


# --------------------------------------------------------------------------- #
# El sistema por debajo
# --------------------------------------------------------------------------- #


class FirewallError(AppError):
    """El firewall subyacente no ha podido cumplir la orden.

    502 y no 500: la aplicacion esta bien, quien ha fallado es el sistema que
    hay detras.
    """

    code = "firewall_error"
    http_status = 502
    message = "El firewall no ha podido aplicar la operacion."


class FirewallCommandError(FirewallError):
    """iptables devolvio un codigo de salida distinto de cero."""

    code = "firewall_command_failed"
    message = "El comando de iptables ha fallado."


class FirewallTimeoutError(FirewallError):
    """iptables no respondio a tiempo, tipicamente esperando el lock de xtables."""

    code = "firewall_timeout"
    http_status = 504
    message = "El comando de iptables ha excedido el tiempo maximo."


class FirewallDriftError(FirewallError):
    """El estado real de iptables no coincide con la base de datos."""

    code = "firewall_drift"
    http_status = 409
    message = "El estado de iptables no coincide con la base de datos."


class SecurityError(AppError):
    """Una invariante de seguridad se ha violado.

    La lanza el `CommandRunner` cuando un argv intenta ejecutar un binario fuera
    de la allowlist (bloque B2). No es un error de usuario: si aparece, hay un
    bug o un intento de abuso, y el mensaje al cliente se queda deliberadamente
    generico mientras el detalle completo va al log.
    """

    code = "security_violation"
    http_status = 500
    message = "Operacion bloqueada por una restriccion de seguridad."
