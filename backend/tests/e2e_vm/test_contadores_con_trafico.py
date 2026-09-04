"""Los contadores, medidos CUANDO el mecanismo actua.

Quinta trampa de la familia de B4, y la unica temporal: leer los contadores en el
instante en que se aplica la regla es no medir nada. Todos valen cero, el arnes se
pone verde y lo que se ha demostrado es que sabe sumar ceros.

Aqui se hace al reves: se aplica la regla, se genera trafico contra ella a
proposito, y solo entonces se lee. Y no basta con "algo subio": la prueba de que
el contador esta atado a SU regla es la pareja -- dos reglas iguales salvo el
destino, trafico contra una sola, y los contadores separados.

SEGURIDAD: todo el trafico va a TEST-NET-3 (203.0.113.0/24) y TEST-NET-2
(198.51.100.0/24), rangos reservados por la RFC 5737 que no existen en Internet ni
en la red de la VM. Se descarta trafico de salida hacia ninguna parte: no hay
forma de que esto corte nada real.
"""

from __future__ import annotations

import contextlib
import socket

import pytest

from app.firewall.iptables import IptablesBackend
from app.firewall.spec import Action, Chain, Protocol, RuleSpec

pytestmark = pytest.mark.requires_iptables

CADENA = Chain.OUTPUT
PUERTO = 9  # discard, RFC 863: nadie lo escucha
DESTINO_CON_TRAFICO = "203.0.113.5"
DESTINO_SIN_TRAFICO = "198.51.100.5"
UUID_CON_TRAFICO = "aa11bb22-cc33-4d44-8e55-ff6677889900"
UUID_SIN_TRAFICO = "11aa22bb-33cc-4d44-8e55-0099887766ff"

#: Intentos de conexion. Cada uno manda al menos un SYN, que es el paquete que la
#: regla descarta. Con el DROP puesto no hay respuesta, asi que cada intento
#: agota su timeout: 5 x 0.2s es un segundo largo de test, no mas.
INTENTOS = 5
ESPERA = 0.2


def _regla(destino: str, uuid: str) -> RuleSpec:
    return RuleSpec(
        chain=CADENA,
        action=Action.DROP,
        protocol=Protocol.TCP,
        dst_ip=destino,
        dst_port=str(PUERTO),
        rule_uuid=uuid,
    )


def _generar_trafico(destino: str) -> None:
    """Golpea la regla. Que la conexion falle es el objetivo, no un problema.

    `suppress(OSError)` y no un `except: pass`: con el DROP puesto, TODOS los
    intentos fallan -- por timeout, por red inalcanzable o por conexion rechazada
    -- y eso es exactamente lo que se busca. Lo que prueba que el trafico salio no
    es esta funcion, sino el contador que se lee despues.
    """
    for _ in range(INTENTOS):
        with contextlib.suppress(OSError):
            socket.create_connection((destino, PUERTO), timeout=ESPERA).close()


def test_el_contador_sube_solo_en_la_regla_que_recibe_el_trafico(
    firewall: IptablesBackend,
) -> None:
    """La pareja: misma regla, distinto destino, y los contadores no se mezclan.

    Sin la mitad "sin trafico", un contador a 8 no distingue "esta regla filtro 8
    paquetes" de "iptables cuenta 8 en todas las reglas de la cadena".
    """
    con_trafico = _regla(DESTINO_CON_TRAFICO, UUID_CON_TRAFICO)
    sin_trafico = _regla(DESTINO_SIN_TRAFICO, UUID_SIN_TRAFICO)

    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, [con_trafico, sin_trafico])

    # Contraprueba temporal: ANTES del trafico, las dos a cero. Es lo que convierte
    # el numero de despues en una medida y no en una casualidad.
    antes = firewall.read_counters(CADENA)
    assert antes[con_trafico.short_uuid].packets == 0
    assert antes[sin_trafico.short_uuid].packets == 0

    _generar_trafico(DESTINO_CON_TRAFICO)

    despues = firewall.read_counters(CADENA)
    assert despues[con_trafico.short_uuid].packets > 0, (
        "la regla no conto ni un paquete: o el trafico no llego a la cadena "
        "gestionada, o el salto desde OUTPUT no esta puesto"
    )
    assert despues[con_trafico.short_uuid].bytes > 0
    assert despues[sin_trafico.short_uuid].packets == 0


def test_los_contadores_se_leen_exactos_y_no_abreviados(firewall: IptablesBackend) -> None:
    """`-x` no es opcional: sin el, iptables abrevia (`500K`) y el `int()` revienta.

    Hallazgo de A2. El fallo es perfecto: invisible en desarrollo, porque hacen
    falta miles de paquetes para que aparezca la abreviatura. Aqui se comprueba lo
    unico comprobable sin generar 500.000 paquetes: que lo que vuelve es un entero
    de verdad, leido de la salida de iptables.
    """
    regla = _regla(DESTINO_CON_TRAFICO, UUID_CON_TRAFICO)
    firewall.ensure_scaffold()
    firewall.apply_ruleset(CADENA, [regla])
    _generar_trafico(DESTINO_CON_TRAFICO)

    contador = firewall.read_counters(CADENA)[regla.short_uuid]

    assert isinstance(contador.packets, int)
    assert isinstance(contador.bytes, int)
    # Un SYN de IPv4 son 60 bytes: si `bytes` viniera abreviado o recortado, esta
    # relacion con `packets` seria absurda.
    assert contador.bytes >= contador.packets * 20
