"""Parametros y specs que comparten la suite de contrato y la de la VM.

Viven fuera de `conftest.py` para poder importarse desde los dos sitios sin
depender de fixtures: son datos, no montaje.

DOS INVARIANTES DE SEGURIDAD, y no son adorno

1. **El prefijo de cadena NO es el de produccion.** Estas pruebas hacen `-F` y
   `-X` sobre las cadenas que crean; si compartieran nombre con las del servicio
   desplegado, un test a medias se llevaria por delante la politica real.
2. **Toda regla que descarta trafico apunta a TEST-NET** (RFC 5737: 192.0.2.0/24,
   198.51.100.0/24, 203.0.113.0/24), rangos reservados para documentacion que no
   existen en Internet ni en la red de la VM. `ensure_scaffold` inserta el salto
   en la POSICION 1 de INPUT/OUTPUT/FORWARD, asi que un `DROP` de esta suite se
   evalua antes que nada: acotarlo a una red imposible es lo que separa un test
   de un auto-bloqueo. B4 ya midio lo que cuesta equivocarse aqui.
"""

from __future__ import annotations

from app.firewall.spec import Action, Chain, Protocol, RuleSpec

__all__ = [
    "CIDR_DE_GESTION",
    "GUARDIANES_POR_CADENA",
    "PARAMETROS_DEL_BACKEND",
    "PREFIJO_DE_PRUEBA",
    "PUERTO_DE_GESTION",
    "PUERTO_DE_RESCATE",
    "UUIDS",
    "specs_de_prueba",
]

#: Ver el invariante 1. `FWDASH` es el del despliegue: aqui no se usa jamas.
PREFIJO_DE_PRUEBA = "FWTEST"

#: Red de laboratorio, deliberadamente NO la del bridge real. Los guardianes de
#: esta suite no tienen que proteger nada: las cadenas de prueba no contienen
#: ningun DROP que pueda alcanzar al administrador (invariante 2). Fijarla hace
#: que la suite diga lo mismo en el Mac y en la VM, que es lo que se compara.
CIDR_DE_GESTION = "192.168.64.0/24"
PUERTO_DE_GESTION = 8000
#: Declarado a proposito: el guardian del ADR-0017 forma parte del contrato desde
#: que existe, y una suite que no lo emitiera dejaria de comparar lo que se
#: ejecuta de verdad en la VM.
PUERTO_DE_RESCATE = 22

#: Cuantos guardianes emite cada cadena con esos parametros. Se fija aqui, a mano,
#: y no llamando al renderer: un test que calcula lo esperado con el mismo codigo
#: que prueba no comprueba nada.
GUARDIANES_POR_CADENA = {Chain.INPUT: 4, Chain.OUTPUT: 4, Chain.FORWARD: 1}

#: Los MISMOS parametros para los dos backends. Que salgan de aqui y no de
#: `Settings` es deliberado: si el `.env` de la maquina pudiera darle valores
#: distintos al fake y al real, esta suite compararia dos cosas que ya no son
#: comparables -- y arrastraria el fallo de A4, en el que un archivo que ni
#: siquiera esta en el repositorio cambiaba el resultado de los tests.
PARAMETROS_DEL_BACKEND = {
    "chain_prefix": PREFIJO_DE_PRUEBA,
    "management_port": PUERTO_DE_GESTION,
    "management_cidr": CIDR_DE_GESTION,
    "management_ssh_port": PUERTO_DE_RESCATE,
}

#: uuids fijos. Fijos y no aleatorios para que un fallo se lea igual dos veces.
UUIDS = (
    "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "b1a7c9d2-1f3e-4a5b-8c7d-9e0f1a2b3c4d",
    "0c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
)


def specs_de_prueba(chain: Chain = Chain.INPUT) -> list[RuleSpec]:
    """Cuatro reglas que cubren lo que el modelo sabe expresar.

    Se eligen para que el viaje de ida y vuelta signifique algo: iptables
    REESCRIBE lo que se le manda —añade `-m tcp`, ordena los flags a su manera,
    normaliza la mascara—, asi que si estas cuatro vuelven identicas por
    estructura, el [[ADR-0006]] esta cerrado de verdad y no por casualidad.

    Todas las que descartan trafico van contra TEST-NET (invariante 2 del modulo).
    """
    origen, destino = ("src_ip", "dst_ip") if chain is Chain.INPUT else ("dst_ip", "src_ip")

    def spec(**campos: object) -> RuleSpec:
        return RuleSpec(chain=chain, **campos)  # type: ignore[arg-type]

    return [
        # tcp con puerto: el caso comun, y el que iptables reescribe con `-m tcp`.
        spec(
            action=Action.DROP,
            protocol=Protocol.TCP,
            **{origen: "203.0.113.10"},
            dst_port="22",
            rule_uuid=UUIDS[0],
        ),
        # udp, red entera y comentario de usuario: la etiqueta lleva tres partes.
        spec(
            action=Action.ACCEPT,
            protocol=Protocol.UDP,
            **{origen: "198.51.100.0/24"},
            dst_port="53",
            comment="dns del laboratorio",
            rule_uuid=UUIDS[1],
        ),
        # icmp: no admite puertos, y el renderer lo emite sin ninguno.
        spec(action=Action.REJECT, protocol=Protocol.ICMP, **{origen: "192.0.2.7"}),
        # sin protocolo y con las dos IPs: `-p all` no se emite.
        spec(
            action=Action.DROP,
            **{origen: "203.0.113.0/24", destino: "192.0.2.0/24"},
            rule_uuid=UUIDS[2],
        ),
    ]
