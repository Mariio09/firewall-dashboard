"""Tipos frontera de la capa de firewall.

Bloque A3. `RuleSpec` es el tipo que cruza la frontera entre la logica de negocio
y el sistema operativo: inmutable, sin dependencias de ORM ni de HTTP, y validado
en construccion.

El flujo completo de una regla atraviesa tres validaciones distintas, porque cada
una protege de algo distinto:

    RuleCreate (Pydantic)  -> protege el CONTRATO de la API
      -> Rule (SQLAlchemy) -> protege la INTEGRIDAD de los datos
        -> RuleSpec        -> protege el SISTEMA
          -> argv: ["iptables", "-A", "FWDASH_INPUT", "-s", "1.2.3.4/32", "-j", "DROP"]

`RuleSpec` es ademas el UNICO formato en el que dos reglas se comparan (ADR-0006):
iptables reescribe lo que le mandas, asi que comparar texto da divergencia
siempre. Por eso se construye canonica (IPs en CIDR, puertos normalizados) y por
eso el parser tiene que poder producir specs, no solo lineas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

__all__ = [
    "COMMENT_TAG",
    "GUARDIAN_TAG_PREFIX",
    "Action",
    "ApplyResult",
    "Chain",
    "Counters",
    "IPVersion",
    "NativeRule",
    "Protocol",
    "RuleSpec",
    "SyncState",
    "Table",
]

# --------------------------------------------------------------------------- #
# Vocabulario compartido entre renderer y parser
# --------------------------------------------------------------------------- #

#: Toda regla que escribe la aplicacion lleva un `-m comment --comment` que
#: empieza por esto. Es lo que distingue "mio" de "ajeno" al leer una cadena, y
#: lo que permite volver a atar un contador a la fila que lo origino.
COMMENT_TAG = "fwdash"

#: Las reglas guardian no salen de la base de datos y no se pueden borrar por API,
#: asi que se etiquetan aparte: al detectar drift no deben buscarse en `rules`.
GUARDIAN_TAG_PREFIX = f"{COMMENT_TAG}:guardian"


# --------------------------------------------------------------------------- #
# Enumeraciones del dominio
# --------------------------------------------------------------------------- #


class Chain(StrEnum):
    """Cadenas del sistema gestionadas por la aplicacion."""

    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    FORWARD = "FORWARD"


class Table(StrEnum):
    """Tablas de iptables. El MVP solo usa `filter`."""

    FILTER = "filter"


class Action(StrEnum):
    """Targets permitidos para una regla de usuario.

    `LOG` no aparece aqui a proposito: no es una accion que el usuario elija, sino
    una regla adicional que el renderer emite cuando `log_enabled` esta activo
    (fase 2).
    """

    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


class IPVersion(IntEnum):
    """Familia de direcciones.

    El modelo la soporta desde la primera migracion, pero el MVP solo genera
    reglas v4. Añadir v6 sera una implementacion mas del backend (`ip6tables`),
    sin migracion de esquema. Ver docs/ARCHITECTURE.md §9.1.
    """

    V4 = 4
    V6 = 6


class SyncState(StrEnum):
    """Estado de sincronizacion entre la DB y iptables.

    Esta distincion es el corazon del diseño: una regla puede existir en la DB y
    no estar aplicada al sistema.
    """

    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    DRIFT = "drift"


# --------------------------------------------------------------------------- #
# Tipos frontera
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Descripcion completa e inmutable de una regla, lista para renderizar.

    No se puede construir invalida: `__post_init__` pasa cada campo por su
    validador y aplica el resultado NORMALIZADO. Esa es la respuesta real a
    "validacion centralizada": no esta en un sitio por convencion, esta en el
    unico sitio por el que es posible pasar.

    Dos consecuencias de que la normalizacion ocurra aqui:

      - `RuleSpec(src_ip="1.2.3.4")` y `RuleSpec(src_ip="1.2.3.4/32")` son
        iguales por valor, asi que el drift se puede calcular con conjuntos.
      - Un `RuleSpec` que exista es siempre renderizable: el renderer no vuelve a
        validar nada.
    """

    chain: Chain
    action: Action
    protocol: Protocol = Protocol.ALL
    ip_version: int = 4
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    in_interface: str | None = None
    out_interface: str | None = None
    comment: str | None = None
    log_enabled: bool = False
    log_prefix: str | None = None

    #: uuid publico de la fila `rules`. Viaja dentro del `--comment` de la regla
    #: (`fwdash:<uuid8>`) y es la clave con la que los contadores leidos de
    #: iptables vuelven a la fila que los origino. `None` en las specs que no
    #: nacen de la base de datos: las de los tests y las de un `preview`.
    #:
    #: `compare=False` a proposito: la identidad NO es parte de la semantica de
    #: la regla. Dos reglas que filtran lo mismo son la misma regla aunque sean
    #: filas distintas, y el drift compara lo que el firewall hace, no quien lo
    #: pidio (ADR-0006). Ademas el parser solo recupera 8 caracteres del uuid
    #: desde el comentario, asi que incluirlo en la comparacion haria que ninguna
    #: regla leida coincidiera nunca con la de la base de datos.
    rule_uuid: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        # Import diferido: `validators` importa este modulo para los enums, asi
        # que hacerlo arriba crearia un ciclo. Es el unico import diferido del
        # paquete y existe solo por esta razon.
        from app.firewall import validators

        object.__setattr__(self, "chain", validators.validate_chain(self.chain))
        object.__setattr__(self, "action", validators.validate_action(self.action))
        object.__setattr__(self, "protocol", validators.validate_protocol(self.protocol))
        object.__setattr__(self, "ip_version", validators.validate_ip_version(self.ip_version))

        for campo in ("src_ip", "dst_ip"):
            valor: str | None = getattr(self, campo)
            if valor is not None:
                object.__setattr__(
                    self,
                    campo,
                    validators.validate_ip_or_cidr(valor, ip_version=self.ip_version, campo=campo),
                )

        for campo in ("src_port", "dst_port"):
            valor = getattr(self, campo)
            if valor is not None:
                object.__setattr__(self, campo, validators.validate_port_spec(valor, campo=campo))

        for campo in ("in_interface", "out_interface"):
            valor = getattr(self, campo)
            if valor is not None:
                object.__setattr__(self, campo, validators.validate_interface(valor, campo=campo))

        if self.comment is not None:
            object.__setattr__(self, "comment", validators.validate_comment(self.comment))

        if self.log_prefix is not None:
            object.__setattr__(self, "log_prefix", validators.validate_log_prefix(self.log_prefix))

        if self.rule_uuid is not None:
            object.__setattr__(self, "rule_uuid", validators.validate_rule_uuid(self.rule_uuid))

        object.__setattr__(self, "log_enabled", bool(self.log_enabled))

        validators.validate_spec(self)

    @property
    def short_uuid(self) -> str | None:
        """Los 8 primeros caracteres del uuid, que son los que van al comentario.

        Ocho caracteres hexadecimales son 4.300 millones de combinaciones: de
        sobra para las reglas de una cadena, y la diferencia entre un comentario
        legible en `iptables -L` y uno que ocupa media linea.
        """
        return None if self.rule_uuid is None else self.rule_uuid[:8]


@dataclass(frozen=True, slots=True)
class Counters:
    """Contadores de paquetes/bytes que iptables mantiene por regla."""

    packets: int = 0
    bytes: int = 0


@dataclass(frozen=True, slots=True)
class NativeRule:
    """Una regla tal y como la reporta iptables, ya parseada.

    Es la mitad de un round-trip, no un lector suelto (ADR-0006): para poder
    comparar el estado real contra la base de datos, el parser rellena `spec` con
    la `RuleSpec` equivalente siempre que la regla caiga dentro del subconjunto
    que la aplicacion sabe expresar.

    Cuando no cae, `spec` es `None` y `unsupported` dice por que. Eso pasa con
    tres cosas distintas, y las tres importan:

      - Los guardianes, que el renderer emite pero no salen de la DB
        (`is_guardian` los reconoce por su etiqueta).
      - Las reglas de cierre de cadena (`-j DROP`, `-j RETURN`).
      - Reglas ajenas o mas expresivas que el modelo (`multiport`, `limit`,
        negaciones). Que aparezcan en una cadena gestionada ES drift, y por eso
        se conservan en vez de descartarse en silencio.

    `raw` guarda siempre la linea original: es lo que se enseña en la UI y en el
    log cuando hay que explicar una divergencia.
    """

    raw: str
    chain: str
    target: str | None = None
    comment: str | None = None
    rule_uuid: str | None = None
    #: `--log-prefix` leido de una regla `-j LOG`. El parser lo usa para devolver
    #: la pareja LOG + accion como una sola `RuleSpec` con `log_enabled=True`.
    log_prefix: str | None = None
    counters: Counters = field(default_factory=Counters)
    spec: RuleSpec | None = None
    unsupported: tuple[str, ...] = ()

    @property
    def is_guardian(self) -> bool:
        """Regla guardian emitida por el renderer, no fila de la tabla `rules`."""
        return self.comment is not None and self.comment.startswith(GUARDIAN_TAG_PREFIX)

    @property
    def is_managed(self) -> bool:
        """Regla escrita por esta aplicacion, guardianes incluidos."""
        return self.comment is not None and self.comment.startswith(f"{COMMENT_TAG}:")


@dataclass(frozen=True, slots=True)
class ApplyResult:
    """Resultado de una reconciliacion sobre una cadena."""

    chain: Chain
    applied: int = 0
    commands: tuple[tuple[str, ...], ...] = ()
    dry_run: bool = False
