"""Punto de entrada de la aplicacion FastAPI.

Se usa el patron de factoria (`create_app`) en lugar de una instancia global
porque permite construir una app limpia por test, con dependencias sobreescritas.

    uvicorn app.main:app --host 0.0.0.0 --port 8000

El `lifespan` construye el backend de firewall, ejecuta `ensure_scaffold()` (B3)
y **reconcilia la politica guardada contra el firewall** (C2): tras un reinicio
de la VM las cadenas gestionadas nacen vacias, y sin ese paso la politica
seguiria viva solo en SQLite hasta que alguien llamase a `/firewall/apply` a
mano. Ver `docs/adr/0018-la-politica-se-reconcilia-al-arrancar.md`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.base import RequestResponseEndpoint

from app.api.deps import build_firewall_backend
from app.api.errors import register_exception_handlers
from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.exceptions import AppError
from app.core.logging import (
    bind_request_context,
    clear_request_context,
    configure_logging,
    get_logger,
    new_request_id,
)
from app.db.session import get_sessionmaker
from app.firewall.base import FirewallBackend
from app.services import firewall_service

__all__ = ["app", "create_app"]

logger = get_logger(__name__)

#: Cabecera estandar de facto para propagar el identificador de peticion.
REQUEST_ID_HEADER = "X-Request-ID"


def _fabrica_de_sesiones(application: FastAPI) -> Callable[[], Session]:
    """La fabrica de sesiones de ESTA aplicacion, para el codigo sin peticion.

    El `lifespan` necesita una sesion de base de datos y no puede pedirla por
    inyeccion: `get_db` es una dependencia de FastAPI y no hay peticion todavia.

    Por defecto es la misma fabrica global que usa `get_db`, asi que el arranque
    habla exactamente con la base de datos con la que hablan los endpoints. Los
    tests inyectan la suya en `create_app` para que la reconciliacion de arranque
    escriba en la base en memoria y no en la que diga el `.env` de la maquina:
    esa fue la segunda trampa de B5 -- `test_seed.py` leia el `.env` real y salia
    verde en el host y rojo en la VM.
    """
    fabrica: Callable[[], Session] | None = getattr(application.state, "session_factory", None)
    return fabrica if fabrica is not None else get_sessionmaker()


def _reconciliar_al_arrancar(
    application: FastAPI, settings: Settings, firewall: FirewallBackend
) -> None:
    """Devuelve al firewall el estado que describe la base de datos (paso C2).

    Es lo que convierte "las reglas estan guardadas" en "las reglas estan
    puestas" despues de reiniciar: el kernel arranca sin las cadenas gestionadas,
    `ensure_scaffold` las crea VACIAS —montar no es poblar, invariante del
    contrato de B5— y los guardianes y las reglas del usuario entran con el
    primer `apply_ruleset`. Ese primer apply es este.

    Se reconstruyen las tres cadenas SIEMPRE, tambien cuando no hay ninguna regla
    guardada. No es un caso especial que sobre: con la politica vacia lo que
    escribe `apply_chains` son las reglas guardian, y tenerlas puestas desde el
    arranque significa que el puerto de gestion queda protegido ANTES de que
    exista la primera regla capaz de cerrarlo. Un `if no hay reglas: no toques`
    ahorraria tres comandos a cambio de dejar esa ventana abierta.

    `AUTO_APPLY=false` lo apaga, y es coherente con lo que esa variable significa
    en el resto de la aplicacion: "no escribas en el firewall por tu cuenta". Un
    arranque no es una excepcion a eso.

    Un fallo aqui NO impide arrancar (ADR-0015, ADR-0018). `apply_chains` ya deja
    las reglas afectadas en `failed` con su `last_error` y lo registra en la
    auditoria; lo que se hace aqui es no propagarlo. Un dashboard de firewall que
    se niega a arrancar cuando el firewall falla es justo el que no puedes abrir
    para averiguar por que falla.
    """
    if not settings.auto_apply:
        logger.info("reconciliacion_de_arranque_omitida", motivo="auto_apply=false")
        return

    fabrica = _fabrica_de_sesiones(application)
    try:
        with fabrica() as session:
            # `actor_name` y no un usuario: aqui no hay nadie. La fila de
            # auditoria tiene que poder distinguirse de un apply de una cuenta
            # borrada, que tambien llega con el usuario vacio.
            respuesta = firewall_service.apply_chains(
                session, firewall, actor_name="sistema:arranque"
            )
    except (AppError, SQLAlchemyError) as exc:
        # `exc_info` no es opcional: el mensaje de un `AppError` esta saneado a
        # proposito para poder devolverse al cliente, asi que sin la traza no
        # queda en ningun sitio que fue lo que fallo.
        logger.warning(
            "reconciliacion_de_arranque_fallida",
            backend=settings.firewall_backend,
            motivo=str(exc),
            exc_info=exc,
        )
        return

    logger.info(
        "politica_reconciliada",
        backend=settings.firewall_backend,
        cadenas={aplicada.chain.value: aplicada.applied for aplicada in respuesta.chains},
    )


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
    # El backend de firewall se construye UNA vez por aplicacion y vive en
    # `app.state`: con el fake, las cadenas estan en memoria, y una instancia
    # nueva por peticion significaria aplicar sobre un objeto y leer otro vacio.
    # `api/deps.py` lo recoge de ahi.
    try:
        firewall = build_firewall_backend(settings)
        firewall.ensure_scaffold()
    except AppError as exc:
        # Desde B3 esto ya no es "aun no implementado" sino el caso real: iptables
        # que no esta, `IPTABLES_BIN` mal configurado, o el servicio sin
        # CAP_NET_ADMIN (ADR-0003). La aplicacion arranca IGUAL, a proposito:
        # `/health` y `/auth` no necesitan firewall, y un dashboard de firewall
        # que se niega a arrancar justo cuando el firewall falla es un dashboard
        # que no sirve para diagnosticar nada — ademas de un bucle de reinicios
        # en systemd cuya unica traza esta en el journal.
        #
        # `app.state.firewall` se queda sin poner, asi que la primera peticion a
        # `/firewall/*` lo reintenta (`deps.get_firewall_backend`) y devuelve el
        # error de verdad al cliente, con su codigo y su status.
        logger.warning(
            "firewall_no_disponible",
            backend=settings.firewall_backend,
            codigo=exc.code,
            motivo=str(exc),
        )
    else:
        application.state.firewall = firewall
        logger.info("firewall_preparado", backend=settings.firewall_backend)
        # C2. Va DESPUES de publicar el backend en `app.state`: si la
        # reconciliacion falla, la aplicacion queda con su firewall montado y
        # `/firewall/status` puede contar lo que pasa. Al reves, un fallo aqui
        # dejaria la aplicacion sin backend por un motivo que no es el suyo.
        _reconciliar_al_arrancar(application, settings, firewall)

    yield
    logger.info("aplicacion_detenida")


def create_app(
    settings: Settings | None = None,
    *,
    session_factory: Callable[[], Session] | None = None,
) -> FastAPI:
    """Construye la aplicacion.

    `session_factory` solo lo necesita el `lifespan`, que es el unico codigo de
    la aplicacion que corre fuera de una peticion y por tanto no puede recibir la
    sesion por inyeccion. Se deja pasar para que los tests apunten la
    reconciliacion de arranque a su base en memoria; en produccion se omite y se
    usa la misma fabrica global que `get_db`.
    """
    settings = settings or get_settings()
    configure_logging(settings)

    application = FastAPI(
        title="firewall-dashboard",
        description="Gestion de reglas de iptables con dashboard web.",
        version="0.0.1",
        lifespan=lifespan,
    )
    application.state.settings = settings
    application.state.session_factory = session_factory

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
