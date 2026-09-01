"""Configuracion de structlog para el logging de la APLICACION.

Bloque A1. No confundir con `packet_logs`, que son los paquetes bloqueados por
iptables (fase 2). Aqui va telemetria: request_id, comandos ejecutados, errores.

Requisito de seguridad: un processor debe censurar por NOMBRE de clave
(password, token, secret, authorization). Ver docs/ARCHITECTURE.md §5.3."""

from __future__ import annotations

import logging
import secrets
import sys
import time
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from app.core.config import Settings

__all__ = [
    "REDACTED",
    "bind_request_context",
    "censor_sensitive",
    "clear_request_context",
    "configure_logging",
    "get_logger",
    "new_request_id",
]

#: Marcador que sustituye a un valor censurado. Que sea reconocible a simple
#: vista importa: un log con `***` dice "aqui habia algo y se oculto", que es
#: informacion util; borrar la clave entera no lo dice.
REDACTED = "***"

#: Se censura por SUBCADENA del nombre de la clave, no por igualdad. Asi
#: `admin_password`, `x-api-key` o `refresh_token` caen sin tener que
#: enumerarlos uno a uno. Confiar en la disciplina de quien escribe el log es
#: exactamente lo que falla el dia que hay prisa.
SENSITIVE_KEY_PARTS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "api_key",
        "apikey",
        "cookie",
        "credential",
        "private_key",
        "hashed_password",
    }
)

#: Profundidad maxima al recorrer estructuras anidadas. Un log no deberia
#: llevar arboles de diez niveles, y una recursion sin tope es un DoS barato.
MAX_CENSOR_DEPTH = 6

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_request_id() -> str:
    """Genera un identificador tipo ULID: 26 caracteres, ordenable por tiempo.

    Se implementa a mano (son quince lineas) en vez de añadir una dependencia.
    Frente a un UUID4 tiene una ventaja concreta al depurar: ordenar los
    identificadores alfabeticamente los ordena cronologicamente.

    La resolucion es el milisegundo. Dos identificadores del mismo milisegundo no
    guardan orden entre si —los 80 bits bajos son aleatorios— y no hace falta:
    sirven para localizar una peticion en el log, no para secuenciarla.
    """
    timestamp_ms = int(time.time() * 1000)
    value = (timestamp_ms << 80) | secrets.randbits(80)
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _censor(value: Any, depth: int = 0) -> Any:
    if depth >= MAX_CENSOR_DEPTH:
        return value
    if isinstance(value, dict):
        return {
            key: REDACTED if _is_sensitive(str(key)) else _censor(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_censor(item, depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_censor(item, depth + 1) for item in value)
    return value


def censor_sensitive(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Processor de structlog: sustituye por `***` todo valor de clave sensible.

    Recorre tambien diccionarios y listas anidados, porque el caso real no es
    `log.info("x", password=...)` sino `log.info("x", payload={"password": ...})`.
    """
    censored = _censor(event_dict)
    # `_censor` devuelve `Any` porque es recursiva; en la raiz siempre es un dict.
    return censored if isinstance(censored, dict) else event_dict


def configure_logging(settings: Settings) -> None:
    """Configura structlog y el logging estandar de forma coherente.

    Idempotente: llamarla dos veces (la aplicacion y un test) no duplica salida.
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=settings.log_level,
        force=True,
    )

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        # El censor va SIEMPRE justo antes del renderer: asi nada de lo que
        # añadan los processors anteriores se escapa sin pasar por el filtro.
        censor_sensitive,
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[settings.log_level]
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> Any:
    """Logger de structlog. Tipado como `Any` porque su tipo real es dinamico."""
    return structlog.get_logger(name)


def bind_request_context(**values: Any) -> None:
    """Ata valores al contexto de la peticion actual (request_id, usuario, ruta).

    Usa `contextvars`, asi que todo log emitido despues —en cualquier capa, sin
    tener que pasar el request_id como argumento— lo lleva incorporado.
    """
    structlog.contextvars.bind_contextvars(**values)


def clear_request_context() -> None:
    """Limpia el contexto. Obligatorio al terminar la peticion."""
    structlog.contextvars.clear_contextvars()
