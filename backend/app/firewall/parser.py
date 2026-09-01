"""Parsea la salida de iptables a estructuras de datos. Funcion pura, sin efectos.

Bloque A3, diseñado contra las fixtures REALES capturadas en A2
(`tests/fixtures/iptables_output/`). No se escribio de memoria a proposito: de las
tres cosas que cambiaron el diseño -- que iptables reescribe la regla, que los
contadores vienen abreviados y que las columnas no son de ancho fijo -- no se
habria adivinado ninguna.

Que devuelve y por que (ADR-0007): cada linea se convierte en un `NativeRule` con
la `RuleSpec` equivalente dentro cuando la regla cae en el subconjunto que la
aplicacion sabe expresar. Cuando no cae, `spec` es `None` y `unsupported` dice por
que. Las reglas que no se pueden expresar NO se descartan: dentro de una cadena
gestionada, que aparezcan es justamente el drift que hay que detectar.

Dos trampas que las fixtures dejaron claras y que estan resueltas aqui:

- **`-j REJECT` vuelve como `-j REJECT --reject-with icmp-port-unreachable`.** Ese
  valor es el por defecto, asi que se ignora; cualquier otro (`icmp-host-prohibited`)
  si hace la regla no representable.
- **Nada de indices de caracter en la salida tabular.** Un target largo
  (`FWDASH_FORWARD`) se come el espaciado. Se usa `split(maxsplit=...)` y el resto
  de la linea se trata como campo libre de matches.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import replace

from app.core.exceptions import FirewallError, InvalidRuleError
from app.firewall.spec import (
    COMMENT_TAG,
    GUARDIAN_TAG_PREFIX,
    Action,
    Chain,
    Counters,
    NativeRule,
    Protocol,
    RuleSpec,
)

__all__ = [
    "parse_counters",
    "parse_human_number",
    "parse_list_format",
    "parse_save_format",
]

#: Sufijos de los contadores abreviados. iptables usa base 1000, no 1024.
_SUFIJOS = {"K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4}

#: Matches que no añaden semantica: `-m tcp` y `-m udp` son el match implicito que
#: iptables hace explicito al guardar, y `-m comment` lo lee este parser aparte.
_MODULOS_TRANSPARENTES = frozenset({"tcp", "udp", "comment"})

#: Valor por defecto de REJECT: iptables lo añade solo, no lo pidio nadie.
_REJECT_POR_DEFECTO = "icmp-port-unreachable"

#: Direcciones que significan "cualquiera" y que por tanto no son un selector.
_CUALQUIER_DIRECCION = frozenset({"0.0.0.0/0", "::/0"})

_CABECERA_CADENA_RE = re.compile(r"^Chain (\S+) \(")
_PREFIJO_LOG_RE = re.compile(r'prefix "(.*?)"')
_COMENTARIO_TABULAR_RE = re.compile(r"/\* (.*?) \*/")
_DST_PORT_RE = re.compile(r"\bdpts?:(\d+(?::\d+)?)")
_SRC_PORT_RE = re.compile(r"\bspts?:(\d+(?::\d+)?)")

#: Marcas de la salida tabular que delatan un match que `RuleSpec` no expresa.
_MARCAS_NO_SOPORTADAS: dict[str, str] = {
    "multiport": "multiport",
    "ctstate": "conntrack",
    "limit:": "limit",
    "icmptype": "icmp-type",
    "state": "state",
    "recent:": "recent",
    "owner": "owner",
}

_ACCIONES = {accion.value for accion in Action}


# --------------------------------------------------------------------------- #
# Ayudas
# --------------------------------------------------------------------------- #


def parse_human_number(value: str) -> int:
    """Convierte los contadores abreviados de iptables a entero: '1543K' -> 1543000.

    La aplicacion lee siempre con `-x` y no deberia encontrarse un sufijo nunca
    ([[Contadores de reglas]]). Esta funcion existe para que, si alguien pega una
    salida sin `-x` -- un runbook, un test, una consola --, el resultado sea un
    numero aproximado y no un `ValueError` a mil paquetes de distancia.
    """
    texto = value.strip()
    if not texto:
        raise FirewallError("Contador vacio en la salida de iptables.")

    multiplicador = 1
    if texto[-1].upper() in _SUFIJOS:
        multiplicador = _SUFIJOS[texto[-1].upper()]
        texto = texto[:-1]

    try:
        return int(float(texto) * multiplicador)
    except ValueError as exc:
        raise FirewallError(
            "No se ha podido leer un contador de iptables.",
            details={"valor": value},
        ) from exc


def _chain_logica(nombre_cadena: str) -> Chain | None:
    """'FWDASH_INPUT' -> Chain.INPUT. Devuelve None si no es una cadena gestionada."""
    try:
        return Chain(nombre_cadena.rsplit("_", 1)[-1].upper())
    except ValueError:
        return None


def _partir_etiqueta(comentario: str | None) -> tuple[str | None, str | None]:
    """Separa `fwdash:<uuid8>:<texto>` en (uuid corto, texto del usuario).

    Un comentario ajeno (sin la etiqueta) vuelve entero como texto: es contenido
    de la regla y hay que conservarlo, pero no identifica nada.
    """
    if comentario is None:
        return None, None
    if not comentario.startswith(f"{COMMENT_TAG}:"):
        return None, comentario
    if comentario.startswith(GUARDIAN_TAG_PREFIX):
        return None, None

    partes = comentario.split(":", 2)
    uuid_corto = partes[1] if len(partes) > 1 and partes[1] != "-" else None
    texto = partes[2] if len(partes) > 2 else None
    return uuid_corto, texto


def _construir_native_rule(
    *,
    raw: str,
    chain: str,
    target: str | None,
    comentario: str | None,
    campos: dict[str, str],
    no_soportado: list[str],
    counters: Counters,
    log_prefix: str | None = None,
) -> NativeRule:
    """Ultimo paso comun a los dos formatos: intentar la spec y empaquetar."""
    uuid_corto, texto_usuario = _partir_etiqueta(comentario)
    es_guardian = comentario is not None and comentario.startswith(GUARDIAN_TAG_PREFIX)

    accion = Action(target) if target is not None and target in _ACCIONES else None

    motivos = list(no_soportado)
    if es_guardian:
        # Un guardian no sale de la tabla `rules`: darle una spec haria que la
        # deteccion de drift lo buscara alli y lo diera por sobrante.
        motivos.append("guardian")
    if target is None:
        motivos.append("sin-target")
    elif accion is None:
        motivos.append(f"target:{target}")

    spec: RuleSpec | None = None
    if not motivos and accion is not None:
        chain_logica = _chain_logica(chain)
        if chain_logica is None:
            motivos.append("cadena-no-gestionada")
        else:
            try:
                spec = RuleSpec(
                    chain=chain_logica,
                    action=accion,
                    protocol=Protocol(campos.get("protocol", Protocol.ALL.value)),
                    src_ip=campos.get("src_ip"),
                    dst_ip=campos.get("dst_ip"),
                    src_port=campos.get("src_port"),
                    dst_port=campos.get("dst_port"),
                    in_interface=campos.get("in_interface"),
                    out_interface=campos.get("out_interface"),
                    comment=texto_usuario,
                )
            except InvalidRuleError as exc:
                motivos.append(f"no-representable:{exc.code}")

    return NativeRule(
        raw=raw,
        chain=chain,
        target=target,
        comment=comentario,
        rule_uuid=uuid_corto,
        log_prefix=log_prefix,
        counters=counters,
        spec=spec,
        unsupported=tuple(motivos),
    )


# --------------------------------------------------------------------------- #
# Formato `iptables -S`
# --------------------------------------------------------------------------- #


def _leer_regla_guardada(linea: str, piezas: list[str], chain: str) -> NativeRule:
    campos: dict[str, str] = {}
    no_soportado: list[str] = []
    target: str | None = None
    comentario: str | None = None

    selectores = {
        "-s": "src_ip",
        "--source": "src_ip",
        "-d": "dst_ip",
        "--destination": "dst_ip",
        "-i": "in_interface",
        "--in-interface": "in_interface",
        "-o": "out_interface",
        "--out-interface": "out_interface",
        "-p": "protocol",
        "--protocol": "protocol",
        "--sport": "src_port",
        "--source-port": "src_port",
        "--dport": "dst_port",
        "--destination-port": "dst_port",
    }

    indice = 0
    while indice < len(piezas):
        pieza = piezas[indice]

        if pieza == "!":
            # La negacion va ANTES del flag, no pegada al valor: `! -s 10.0.0.0/8`.
            no_soportado.append("negacion")
            indice += 1
            continue

        siguiente = piezas[indice + 1] if indice + 1 < len(piezas) else None

        if pieza in selectores and siguiente is not None:
            campos[selectores[pieza]] = siguiente
            indice += 2
            continue

        if pieza in ("-m", "--match") and siguiente is not None:
            if siguiente not in _MODULOS_TRANSPARENTES:
                no_soportado.append(siguiente)
            indice += 2
            continue

        if pieza == "--comment" and siguiente is not None:
            comentario = siguiente
            indice += 2
            continue

        if pieza in ("-j", "--jump") and siguiente is not None:
            target = siguiente
            indice += 2
            continue

        if pieza == "--reject-with" and siguiente is not None:
            if siguiente != _REJECT_POR_DEFECTO:
                no_soportado.append(f"reject-with:{siguiente}")
            indice += 2
            continue

        if pieza == "--log-prefix" and siguiente is not None:
            campos["log_prefix"] = siguiente
            indice += 2
            continue

        if pieza.startswith("-"):
            # Flag desconocido: se anota y se consume tambien su valor si lo tiene.
            no_soportado.append(pieza.lstrip("-"))
            indice += 2 if siguiente is not None and not siguiente.startswith("-") else 1
            continue

        no_soportado.append(f"desconocido:{pieza}")
        indice += 1

    return _construir_native_rule(
        raw=linea,
        chain=chain,
        target=target,
        comentario=comentario,
        campos=campos,
        no_soportado=no_soportado,
        counters=Counters(),
        log_prefix=campos.get("log_prefix"),
    )


def _emparejar_reglas_de_log(reglas: list[NativeRule]) -> list[NativeRule]:
    """Devuelve la pareja LOG + accion como UNA regla logica con `log_enabled`.

    El renderer emite dos lineas por cada regla con log activado, con la misma
    etiqueta y el LOG primero. Al leerlas de vuelta hay que volver a juntarlas: si
    no, la spec de la segunda saldria con `log_enabled=False` y la deteccion de
    drift veria una diferencia con la base de datos en una regla que esta
    perfectamente aplicada, ademas de una linea sobrante que no reconoce.

    Las dos lineas se conservan: `raw` sigue enseñando lo que hay de verdad en la
    cadena. Lo que cambia es que la segunda ya lleva la spec completa.
    """
    resultado: list[NativeRule] = []
    for regla in reglas:
        anterior = resultado[-1] if resultado else None
        emparejable = (
            regla.spec is not None
            and anterior is not None
            and anterior.target == "LOG"
            and anterior.log_prefix is not None
            and anterior.comment is not None
            and anterior.comment == regla.comment
        )
        if emparejable and regla.spec is not None and anterior is not None:
            try:
                spec = replace(regla.spec, log_enabled=True, log_prefix=anterior.log_prefix)
            except InvalidRuleError:
                # Un prefijo que iptables acepto y el modelo no: la regla se queda
                # sin emparejar y el drift la vera. Preferible a inventarse una spec.
                resultado.append(regla)
                continue
            resultado.append(replace(regla, spec=spec))
            continue
        resultado.append(regla)
    return resultado


def parse_save_format(output: str, chain: str) -> list[NativeRule]:
    """Parsea la salida de `iptables -S` (formato de reglas, una por linea).

    Solo devuelve las reglas de `chain`. Las lineas `-P` (politicas) y `-N`
    (creacion de cadenas) se ignoran: describen la cadena, no su contenido.

    Se tokeniza con `shlex` y no con `split()` porque el `--comment` viene
    entrecomillado y puede llevar espacios.
    """
    reglas: list[NativeRule] = []
    for linea_cruda in output.splitlines():
        linea = linea_cruda.strip()
        if not linea.startswith("-A "):
            continue
        try:
            tokens = shlex.split(linea)
        except ValueError as exc:
            raise FirewallError(
                "No se ha podido tokenizar una linea de iptables.",
                details={"linea": linea},
            ) from exc
        if len(tokens) < 2 or tokens[1] != chain:
            continue
        reglas.append(_leer_regla_guardada(linea, tokens[2:], chain))
    return _emparejar_reglas_de_log(reglas)


# --------------------------------------------------------------------------- #
# Formato `iptables -L -v -n [-x]`
# --------------------------------------------------------------------------- #


def _leer_regla_tabular(linea: str, chain: str) -> NativeRule:
    columnas = linea.split(None, 9)
    if len(columnas) < 9:
        raise FirewallError(
            "Linea de `iptables -L -v -n` con menos columnas de las esperadas.",
            details={"linea": linea.strip()},
        )

    paquetes, bytes_, target, protocolo, _opt, entrada, salida, origen, destino = columnas[:9]
    resto = columnas[9] if len(columnas) > 9 else ""

    campos: dict[str, str] = {}
    no_soportado: list[str] = []

    if protocolo not in ("all", "0"):
        campos["protocol"] = protocolo
    if entrada != "*":
        campos["in_interface"] = entrada
    if salida != "*":
        campos["out_interface"] = salida
    for valor, clave in ((origen, "src_ip"), (destino, "dst_ip")):
        if valor.startswith("!"):
            no_soportado.append("negacion")
        elif valor not in _CUALQUIER_DIRECCION:
            campos[clave] = valor

    for marca, motivo in _MARCAS_NO_SOPORTADAS.items():
        if marca in resto:
            no_soportado.append(motivo)

    if "reject-with" in resto and _REJECT_POR_DEFECTO not in resto:
        no_soportado.append("reject-with")

    dst_port = _DST_PORT_RE.search(resto)
    if dst_port:
        campos["dst_port"] = dst_port.group(1)
    src_port = _SRC_PORT_RE.search(resto)
    if src_port:
        campos["src_port"] = src_port.group(1)

    comentario_encontrado = _COMENTARIO_TABULAR_RE.search(resto)
    comentario = comentario_encontrado.group(1) if comentario_encontrado else None
    prefijo_log = _PREFIJO_LOG_RE.search(resto)

    return _construir_native_rule(
        raw=linea.rstrip(),
        chain=chain,
        target=target,
        comentario=comentario,
        campos=campos,
        no_soportado=no_soportado,
        counters=Counters(packets=parse_human_number(paquetes), bytes=parse_human_number(bytes_)),
        log_prefix=prefijo_log.group(1) if prefijo_log else None,
    )


def parse_list_format(output: str, chain: str) -> list[NativeRule]:
    """Parsea la salida de `iptables -L -v -n` (formato tabular, con contadores).

    Es la unica fuente de contadores. La app la pide siempre con `-x`, pero este
    parser tambien lee la abreviada, que es lo que se pega en un runbook.
    """
    reglas: list[NativeRule] = []
    cadena_actual: str | None = None

    for linea in output.splitlines():
        if not linea.strip():
            continue

        cabecera = _CABECERA_CADENA_RE.match(linea)
        if cabecera:
            cadena_actual = cabecera.group(1)
            continue

        if cadena_actual != chain:
            continue
        if linea.split(None, 1)[0] == "pkts":
            continue

        reglas.append(_leer_regla_tabular(linea, chain))

    return reglas


def parse_counters(output: str) -> dict[str, Counters]:
    """Extrae contadores indexados por el uuid del `--comment` de cada regla.

    Recorre TODAS las cadenas de la salida: los contadores se piden de una vez y
    se reparten por uuid, no cadena a cadena.

    Cuando una regla logica produjo dos lineas -- la de LOG y la de accion, que
    comparten etiqueta -- se queda con la ULTIMA, que es la de accion. Sumarlas
    contaria dos veces los mismos paquetes, porque son los mismos: el paquete pasa
    por la regla de LOG y despues por la de accion.
    """
    contadores: dict[str, Counters] = {}
    cadena_actual: str | None = None

    for linea in output.splitlines():
        if not linea.strip():
            continue

        cabecera = _CABECERA_CADENA_RE.match(linea)
        if cabecera:
            cadena_actual = cabecera.group(1)
            continue
        if cadena_actual is None or linea.split(None, 1)[0] == "pkts":
            continue

        comentario = _COMENTARIO_TABULAR_RE.search(linea)
        if comentario is None:
            continue
        uuid_corto, _ = _partir_etiqueta(comentario.group(1))
        if uuid_corto is None:
            continue

        columnas = linea.split(None, 2)
        contadores[uuid_corto] = Counters(
            packets=parse_human_number(columnas[0]), bytes=parse_human_number(columnas[1])
        )

    return contadores
