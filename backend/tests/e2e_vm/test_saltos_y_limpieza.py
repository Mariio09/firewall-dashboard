"""Lo que hay por DEBAJO del Protocol: los saltos y el estado del sistema.

La suite de contrato solo puede mirar por donde mira la aplicacion. Pero
`ensure_scaffold` y `teardown` prometen dos cosas que no se ven desde ahi:

  - que el salto queda en la POSICION 1 de la cadena del sistema, porque si no la
    politica de la aplicacion se evaluaria despues de lo que ya hubiera;
  - que `teardown` deja la maquina EXACTAMENTE como estaba.

Aqui se comprueban con `iptables -S`, que es la fuente de verdad.
"""

from __future__ import annotations

import pytest

from app.firewall.iptables import IptablesBackend
from app.firewall.runner import CommandRunner
from app.firewall.spec import Chain
from tests.contract.casos import PREFIJO_DE_PRUEBA

pytestmark = pytest.mark.requires_iptables


def politica(runner: CommandRunner) -> list[str]:
    """La tabla `filter` entera, tal cual la escribe iptables."""
    return runner.run(["iptables", "-S"]).stdout.splitlines()


def saltos(lineas: list[str], chain: Chain) -> list[str]:
    destino = f"{PREFIJO_DE_PRUEBA}_{chain.value}"
    return [
        linea
        for linea in lineas
        if linea.startswith(f"-A {chain.value} ") and linea.endswith(f"-j {destino}")
    ]


def test_el_salto_se_pone_una_sola_vez_y_en_la_cabecera(
    firewall: IptablesBackend, runner: CommandRunner
) -> None:
    """Idempotencia vista desde el sistema, que es donde se acumularia el fallo.

    `lifespan` llama a `ensure_scaffold` en cada arranque del servicio: un salto
    que se insertara sin preguntar se duplicaria en cada `systemctl restart` hasta
    llenar la cadena. Se llama dos veces a proposito.
    """
    firewall.ensure_scaffold()
    firewall.ensure_scaffold()

    lineas = politica(runner)
    for chain in Chain:
        assert len(saltos(lineas, chain)) == 1, f"salto duplicado en {chain.value}"

    # Y va el PRIMERO de su cadena: lo que la aplicacion filtra se evalua antes
    # que lo que hubiera puesto cualquier otro.
    for chain in Chain:
        reglas_de_la_cadena = [linea for linea in lineas if linea.startswith(f"-A {chain.value} ")]
        assert reglas_de_la_cadena[0].endswith(f"-j {PREFIJO_DE_PRUEBA}_{chain.value}")


def test_teardown_deja_la_tabla_exactamente_como_estaba(
    firewall: IptablesBackend, runner: CommandRunner
) -> None:
    """No "parecida": identica, linea a linea.

    Si esto falla, hay dos posibilidades y las dos importan: que `teardown` deje
    restos, o que algo mas este escribiendo en iptables mientras corre el test
    (el servicio con `FIREWALL_BACKEND=iptables`, ufw, Docker). Ninguna de las dos
    se puede dar por buena.
    """
    antes = politica(runner)

    firewall.ensure_scaffold()
    firewall.apply_ruleset(Chain.INPUT, [])
    assert politica(runner) != antes  # contraprueba: el montaje SI se nota

    firewall.teardown()

    assert politica(runner) == antes


def test_teardown_se_lleva_tambien_los_saltos_duplicados(
    firewall: IptablesBackend, runner: CommandRunner
) -> None:
    """`-D` borra UNA coincidencia: con un duplicado, `-X` fallaria por referencias.

    `ensure_scaffold` no crea duplicados —pregunta con `-C` antes de insertar—,
    pero una mano ajena si puede. El bucle acotado de `teardown` existe por esto, y
    esta es la unica forma de comprobar que sirve: creando el duplicado a mano.
    """
    firewall.ensure_scaffold()
    nombre = f"{PREFIJO_DE_PRUEBA}_{Chain.INPUT.value}"
    runner.run(["iptables", "-I", Chain.INPUT.value, "1", "-j", nombre])
    assert len(saltos(politica(runner), Chain.INPUT)) == 2

    firewall.teardown()

    lineas = politica(runner)
    assert saltos(lineas, Chain.INPUT) == []
    assert not any(nombre in linea for linea in lineas)
