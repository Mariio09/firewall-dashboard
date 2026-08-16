"""Parsea la salida de iptables a estructuras de datos. Funcion pura, sin efectos.

Bloque A3, pero depende de las fixtures capturadas en el paso A2.

IMPORTANTE: no escribir este modulo "de memoria". El formato de salida de iptables
tiene bastantes casos raros (contadores con sufijo K/M/G, modulos de match en orden
variable, cadenas vacias, politicas por defecto, `--comment` con espacios). Los
tests de este archivo, alimentados con salidas REALES guardadas en
`tests/fixtures/iptables_output/`, son los mas valiosos del repositorio: son el
seguro contra que el `FakeFirewallBackend` se desvie de la realidad.

Comandos a capturar en A2 (todos de solo lectura, no modifican nada):

    iptables -S
    iptables -L -v -n
    iptables -S FWDASH_INPUT     # y su error cuando la cadena no existe
    iptables --version
"""

from __future__ import annotations

from app.firewall.spec import Counters, NativeRule


def parse_save_format(output: str, chain: str) -> list[NativeRule]:
    """Parsea la salida de `iptables -S` (formato de reglas, una por linea)."""
    raise NotImplementedError("TODO(A3)")


def parse_list_format(output: str, chain: str) -> list[NativeRule]:
    """Parsea la salida de `iptables -L -v -n` (formato tabular, con contadores)."""
    raise NotImplementedError("TODO(A3)")


def parse_counters(output: str) -> dict[str, Counters]:
    """Extrae contadores indexados por el uuid del `--comment` de cada regla."""
    raise NotImplementedError("TODO(A3)")


def parse_human_number(value: str) -> int:
    """Convierte los contadores abreviados de iptables a entero: '1543K' -> 1543000."""
    raise NotImplementedError("TODO(A3)")
