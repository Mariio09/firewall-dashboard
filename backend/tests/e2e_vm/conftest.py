"""Fixtures de la suite que solo tiene sentido dentro de la VM.

Todo lo de este paquete lleva `pytestmark = pytest.mark.requires_iptables`, asi
que en el host ni se recoge. Lo que se prueba aqui es lo que la suite de contrato
NO puede probar: lo que hay por debajo del Protocol -- los saltos en las cadenas
del sistema, los contadores con trafico encima y la comparacion cara a cara del
fake contra iptables de verdad.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.firewall.iptables import IptablesBackend
from app.firewall.runner import CommandRunner
from tests.iptables_real import backend_real, exigir_iptables_vivo, runner_real


@pytest.fixture
def runner() -> CommandRunner:
    """Acceso directo a iptables, para mirar por debajo del Protocol."""
    ejecutor = runner_real()
    exigir_iptables_vivo(ejecutor)
    return ejecutor


@pytest.fixture
def firewall(runner: CommandRunner) -> Iterator[IptablesBackend]:
    """Backend real, limpio antes y despues.

    El `teardown` de entrada es lo que hace que un test que murio a mitad no
    contamine al siguiente: las cadenas viven en el kernel, no en el proceso.
    """
    backend = backend_real()
    backend.teardown()
    try:
        yield backend
    finally:
        backend.teardown()
