"""Validacion y normalizacion de TODA entrada que acaba en un comando iptables.

Bloque A3. Ningun otro modulo del proyecto tiene permiso para interpretar una IP,
un puerto o un nombre de interfaz. Si aparece `ipaddress.ip_network(...)` fuera de
este archivo, es un bug de arquitectura.

Cada funcion NORMALIZA ademas de validar: devuelve la forma canonica que se guarda
en la base de datos y con la que se compara el drift. Asi `1.2.3.4` y `1.2.3.4/32`
acaban siendo la misma fila, que es lo que evita reglas duplicadas que parecen
distintas (ADR-0006).

Sobre los caracteres prohibidos en los textos libres: NO son la defensa contra la
inyeccion de comandos. Esa esta cerrada por construccion en `runner.py`, que
ejecuta siempre con `shell=False` y argv en lista, asi que un `;` o un `$()` en un
comentario nunca podria interpretarse. Lo que se rechaza aqui es lo que romperia a
iptables o al parser: comillas dobles (delimitan el `--comment` en la salida de
`iptables -S`), barras invertidas y caracteres de control.
"""

from __future__ import annotations

import re
from enum import Enum
from ipaddress import ip_network
from typing import TYPE_CHECKING, TypeVar
from uuid import UUID

from app.core.exceptions import InvalidRuleError
from app.firewall.spec import Action, Chain, IPVersion, Protocol

if TYPE_CHECKING:
    from app.firewall.spec import RuleSpec

__all__ = [
    "MAX_CHAIN_NAME_LEN",
    "MAX_COMMENT_LEN",
    "MAX_INTERFACE_LEN",
    "MAX_LOG_PREFIX_LEN",
    "MAX_PORT",
    "MIN_PORT",
    "validate_action",
    "validate_chain",
    "validate_comment",
    "validate_interface",
    "validate_ip_or_cidr",
    "validate_ip_version",
    "validate_log_prefix",
    "validate_managed_chain_name",
    "validate_port_spec",
    "validate_protocol",
    "validate_rule_uuid",
    "validate_spec",
]

# Longitud maxima real del --log-prefix de iptables (29 caracteres utiles).
MAX_LOG_PREFIX_LEN = 29

# Longitud maxima de un nombre de interfaz en Linux (IFNAMSIZ - 1).
MAX_INTERFACE_LEN = 15

# El --comment de iptables admite 256 bytes. Se reserva margen porque el
# renderer antepone la etiqueta de identidad `fwdash:<uuid8>:`.
MAX_COMMENT_LEN = 200

# Nombre de cadena maximo en xtables (XT_EXTENSION_MAXNAMELEN - 1).
MAX_CHAIN_NAME_LEN = 28

MIN_PORT = 1
MAX_PORT = 65535

#: Unicos protocolos que admiten puertos. `icmp` y `all` no tienen concepto de puerto
#: y iptables rechaza la regla entera si se le pasa uno.
PROTOCOLOS_CON_PUERTO: frozenset[Protocol] = frozenset({Protocol.TCP, Protocol.UDP})

_INTERFACE_RE = re.compile(rf"^[A-Za-z0-9@._-]{{1,{MAX_INTERFACE_LEN}}}$")
_PORT_SPEC_RE = re.compile(r"^\d{1,5}(?::\d{1,5})?$")
_CHAIN_PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,20}$")

#: Comilla doble: delimita el --comment en la salida de iptables, meterla dentro
#: romperia el parser. Barra invertida: iptables la usa para escapar.
_CARACTERES_PROHIBIDOS = frozenset('"\\')

_E = TypeVar("_E", bound=Enum)


# --------------------------------------------------------------------------- #
# Ayudas internas
# --------------------------------------------------------------------------- #


def _asegurar_str(value: object, campo: str) -> str:
    """Rechaza lo que no es texto ANTES de interpretarlo.

    No es paranoia gratuita: `ipaddress.ip_network(5)` no falla, devuelve
    `0.0.0.5/32`. Un entero colado desde el ORM se convertiria en una regla
    valida que nadie escribio.
    """
    if not isinstance(value, str):
        raise InvalidRuleError(
            f"El campo '{campo}' debe ser texto.",
            details={"campo": campo, "tipo": type(value).__name__},
        )
    return value


def _rechazar_caracteres_prohibidos(texto: str, campo: str) -> None:
    malos = sorted({c for c in texto if c in _CARACTERES_PROHIBIDOS or not c.isprintable()})
    if malos:
        raise InvalidRuleError(
            f"El campo '{campo}' contiene caracteres no permitidos.",
            details={"campo": campo, "caracteres": [repr(c) for c in malos]},
        )


def _validar_enum(enum_cls: type[_E], value: object, campo: str) -> _E:
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise InvalidRuleError(
            f"'{value}' no es un valor valido de '{campo}'.",
            details={
                "campo": campo,
                "valor": str(value),
                "permitidos": [str(miembro.value) for miembro in enum_cls],
            },
        ) from exc


def _puerto_en_rango(puerto: int, *, campo: str, valor: str) -> None:
    if not MIN_PORT <= puerto <= MAX_PORT:
        raise InvalidRuleError(
            f"El puerto {puerto} esta fuera del rango {MIN_PORT}-{MAX_PORT}.",
            details={"campo": campo, "valor": valor},
        )


# --------------------------------------------------------------------------- #
# Validadores de campo
# --------------------------------------------------------------------------- #


def validate_ip_or_cidr(value: str, *, ip_version: int = 4, campo: str = "ip") -> str:
    """Valida una IP o red y la devuelve normalizada a notacion CIDR.

    `'1.2.3.4'` -> `'1.2.3.4/32'`. Con `strict=False` los bits de host de una red
    se ponen a cero (`'10.0.0.1/8'` -> `'10.0.0.0/8'`), que es exactamente lo que
    hace iptables con el mismo valor: normalizar igual que el sistema es lo que
    permite comparar despues.
    """
    texto = _asegurar_str(value, campo).strip()
    if not texto:
        raise InvalidRuleError(
            f"El campo '{campo}' no puede estar vacio.", details={"campo": campo}
        )
    try:
        red = ip_network(texto, strict=False)
    except ValueError as exc:
        raise InvalidRuleError(
            f"'{texto}' no es una direccion IP ni una red valida.",
            details={"campo": campo, "valor": texto},
        ) from exc
    if red.version != ip_version:
        raise InvalidRuleError(
            f"'{texto}' es IPv{red.version} pero la regla es IPv{ip_version}.",
            details={"campo": campo, "valor": texto, "ip_version": ip_version},
        )
    return str(red)


def validate_port_spec(value: str, *, campo: str = "puerto") -> str:
    """Valida un puerto o un rango de puertos y lo devuelve normalizado.

    Acepta `'80'` y `'8000:8010'`. Rechaza `0`, todo lo que pase de 65535, los
    rangos invertidos y cualquier cosa que no sean digitos y como mucho un ':'.
    Normaliza los ceros a la izquierda: `'0080'` -> `'80'`.
    """
    texto = _asegurar_str(value, campo).strip()
    if not _PORT_SPEC_RE.match(texto):
        raise InvalidRuleError(
            f"'{texto}' no es un puerto ni un rango de puertos valido. "
            "Formatos aceptados: '80' o '8000:8010'.",
            details={"campo": campo, "valor": texto},
        )

    if ":" in texto:
        inicio_txt, fin_txt = texto.split(":")
        inicio, fin = int(inicio_txt), int(fin_txt)
        _puerto_en_rango(inicio, campo=campo, valor=texto)
        _puerto_en_rango(fin, campo=campo, valor=texto)
        if inicio >= fin:
            raise InvalidRuleError(
                f"El rango '{texto}' esta invertido o vacio: el puerto inicial debe ser "
                "menor que el final. Para un solo puerto, escribelo sin ':'.",
                details={"campo": campo, "valor": texto},
            )
        return f"{inicio}:{fin}"

    puerto = int(texto)
    _puerto_en_rango(puerto, campo=campo, valor=texto)
    return str(puerto)


def validate_interface(value: str, *, campo: str = "interfaz") -> str:
    """Valida un nombre de interfaz de red (`eth0`, `enp0s1`, `lo`).

    No se admite el comodin `eth+` de iptables: una regla que abarca interfaces
    que todavia no existen es justo lo que no se quiere poder escribir desde una
    UI web.
    """
    texto = _asegurar_str(value, campo).strip()
    if not _INTERFACE_RE.match(texto):
        raise InvalidRuleError(
            f"'{texto}' no es un nombre de interfaz valido "
            f"(hasta {MAX_INTERFACE_LEN} caracteres alfanumericos, '@', '.', '_' o '-').",
            details={"campo": campo, "valor": texto},
        )
    return texto


def validate_log_prefix(value: str, *, campo: str = "log_prefix") -> str:
    """Valida un `--log-prefix`: longitud acotada, sin comillas ni control.

    No se hace `strip()` a proposito: el espacio final (`'FWDASH DROP: '`) es la
    convencion habitual para que el prefijo no se pegue al resto de la linea de
    syslog, y quitarlo cambiaria lo que el usuario escribio.
    """
    texto = _asegurar_str(value, campo)
    if not texto.strip():
        raise InvalidRuleError("El prefijo de log no puede estar vacio.", details={"campo": campo})
    if len(texto) > MAX_LOG_PREFIX_LEN:
        raise InvalidRuleError(
            f"El prefijo de log no puede pasar de {MAX_LOG_PREFIX_LEN} caracteres "
            f"(tiene {len(texto)}).",
            details={"campo": campo, "valor": texto, "longitud": len(texto)},
        )
    _rechazar_caracteres_prohibidos(texto, campo)
    return texto


def validate_comment(value: str, *, campo: str = "comment") -> str:
    """Valida el comentario libre que viaja dentro del `--comment` de la regla."""
    texto = _asegurar_str(value, campo).strip()
    if not texto:
        raise InvalidRuleError("El comentario no puede estar vacio.", details={"campo": campo})
    if len(texto) > MAX_COMMENT_LEN:
        raise InvalidRuleError(
            f"El comentario no puede pasar de {MAX_COMMENT_LEN} caracteres (tiene {len(texto)}).",
            details={"campo": campo, "longitud": len(texto)},
        )
    _rechazar_caracteres_prohibidos(texto, campo)
    return texto


def validate_rule_uuid(value: str, *, campo: str = "rule_uuid") -> str:
    """Valida el uuid publico de la fila `rules`, que viaja dentro del comentario.

    Se valida porque acaba formando parte de un argv y porque es la clave con la
    que se vuelven a atar los contadores a la fila que los origino: un uuid
    malformado no rompe nada visible, simplemente hace que los contadores dejen
    de cuadrar, que es un fallo mucho peor.
    """
    texto = _asegurar_str(value, campo).strip()
    try:
        return str(UUID(texto))
    except ValueError as exc:
        raise InvalidRuleError(
            f"'{texto}' no es un uuid valido.",
            details={"campo": campo, "valor": texto},
        ) from exc


def validate_chain(value: object, *, campo: str = "chain") -> Chain:
    """Convierte a `Chain` cualquier entrada, o falla."""
    return _validar_enum(Chain, value, campo)


def validate_action(value: object, *, campo: str = "action") -> Action:
    return _validar_enum(Action, value, campo)


def validate_protocol(value: object, *, campo: str = "protocol") -> Protocol:
    return _validar_enum(Protocol, value, campo)


def validate_ip_version(value: object, *, campo: str = "ip_version") -> int:
    """Acepta 4 o 6 y devuelve un `int` plano.

    Devuelve `int` y no `IPVersion` porque es lo que declara el modelo y lo que
    guarda SQLite; `IPVersion` es un `IntEnum`, asi que la comparacion con 4
    sigue funcionando en ambos sentidos.
    """
    return int(_validar_enum(IPVersion, value, campo))


def validate_managed_chain_name(prefix: str, chain: Chain) -> str:
    """Construye y valida el nombre de la cadena gestionada: 'FWDASH' + INPUT -> 'FWDASH_INPUT'."""
    texto = _asegurar_str(prefix, "managed_chain_prefix").strip()
    if not _CHAIN_PREFIX_RE.match(texto):
        raise InvalidRuleError(
            f"'{texto}' no es un prefijo de cadena valido "
            "(mayusculas, digitos y '_', empezando por letra).",
            details={"campo": "managed_chain_prefix", "valor": texto},
        )
    nombre = f"{texto}_{validate_chain(chain).value}"
    if len(nombre) > MAX_CHAIN_NAME_LEN:
        raise InvalidRuleError(
            f"El nombre de cadena '{nombre}' pasa de {MAX_CHAIN_NAME_LEN} caracteres, "
            "que es el maximo de iptables.",
            details={"campo": "managed_chain_prefix", "valor": nombre},
        )
    return nombre


# --------------------------------------------------------------------------- #
# Validacion cruzada de la spec completa
# --------------------------------------------------------------------------- #


def validate_spec(spec: RuleSpec) -> None:
    """Valida las reglas que ningun validador por campo puede ver.

    Se llama desde `RuleSpec.__post_init__`, DESPUES de que cada campo se haya
    normalizado. Todo lo que se comprueba aqui lo rechazaria tambien iptables,
    pero fallar aqui devuelve un 422 con una explicacion en vez de un 502 con el
    stderr de un comando.
    """
    if (spec.src_port is not None or spec.dst_port is not None) and (
        spec.protocol not in PROTOCOLOS_CON_PUERTO
    ):
        raise InvalidRuleError(
            f"El protocolo '{spec.protocol.value}' no admite puertos: solo tcp y udp los tienen.",
            details={"campo": "protocol", "valor": spec.protocol.value},
        )

    if spec.chain is Chain.INPUT and spec.out_interface is not None:
        raise InvalidRuleError(
            "La cadena INPUT no admite interfaz de salida: cuando el paquete la "
            "atraviesa todavia no se ha decidido por donde saldra.",
            details={"campo": "out_interface", "chain": spec.chain.value},
        )

    if spec.chain is Chain.OUTPUT and spec.in_interface is not None:
        raise InvalidRuleError(
            "La cadena OUTPUT no admite interfaz de entrada: el paquete lo genera "
            "la propia maquina, no entra por ninguna interfaz.",
            details={"campo": "in_interface", "chain": spec.chain.value},
        )

    if spec.log_enabled and not spec.log_prefix:
        raise InvalidRuleError(
            "Una regla con log activado necesita un prefijo con el que reconocerla "
            "despues en syslog.",
            details={"campo": "log_prefix"},
        )
