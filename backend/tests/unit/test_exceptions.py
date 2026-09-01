"""La jerarquia de errores: cada nivel sabe traducirse a HTTP por si solo."""

from __future__ import annotations

import pytest

from app.core.exceptions import (
    AppError,
    AuthError,
    ConflictError,
    FirewallCommandError,
    FirewallDriftError,
    FirewallError,
    FirewallTimeoutError,
    ForbiddenError,
    InvalidRuleError,
    NotFoundError,
    SecurityError,
    ValidationError,
)


@pytest.mark.parametrize(
    ("excepcion", "status", "code"),
    [
        (ValidationError, 422, "validation_error"),
        (InvalidRuleError, 422, "invalid_rule"),
        (NotFoundError, 404, "not_found"),
        (ConflictError, 409, "conflict"),
        (AuthError, 401, "unauthorized"),
        (ForbiddenError, 403, "forbidden"),
        (FirewallError, 502, "firewall_error"),
        (FirewallCommandError, 502, "firewall_command_failed"),
        (FirewallTimeoutError, 504, "firewall_timeout"),
        (FirewallDriftError, 409, "firewall_drift"),
        (SecurityError, 500, "security_violation"),
    ],
)
def test_cada_error_conoce_su_status_y_su_codigo(
    excepcion: type[AppError], status: int, code: str
) -> None:
    error = excepcion()
    assert error.http_status == status
    assert error.code == code


def test_todo_error_de_dominio_desciende_de_app_error() -> None:
    """Un unico `except AppError` en el handler cubre la jerarquia entera."""
    assert issubclass(InvalidRuleError, ValidationError)
    assert issubclass(FirewallCommandError, FirewallError)
    for excepcion in (ValidationError, NotFoundError, AuthError, FirewallError):
        assert issubclass(excepcion, AppError)


def test_forbidden_no_ensombrece_el_builtin() -> None:
    """`PermissionError` de Python es un `OSError` y aparece al tocar ficheros.

    Reutilizar ese nombre haria que un `except PermissionError` capturase cosas
    de dos mundos distintos sin que nadie lo notara.
    """
    assert not issubclass(ForbiddenError, OSError)


def test_el_mensaje_y_los_detalles_viajan() -> None:
    error = InvalidRuleError(
        "El puerto '99999' esta fuera del rango valido (1-65535).",
        details={"field": "dst_port"},
    )
    assert error.to_dict() == {
        "code": "invalid_rule",
        "message": "El puerto '99999' esta fuera del rango valido (1-65535).",
        "details": {"field": "dst_port"},
    }


def test_sin_mensaje_se_usa_el_de_la_clase() -> None:
    assert NotFoundError().message == "El recurso solicitado no existe."


def test_el_mensaje_de_una_instancia_no_contamina_la_clase() -> None:
    """`self.message = ...` sobre un atributo de clase es un error clasico."""
    NotFoundError("La regla no existe.")
    assert NotFoundError().message == "El recurso solicitado no existe."
