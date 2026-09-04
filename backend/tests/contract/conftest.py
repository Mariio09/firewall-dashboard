"""El mismo test, contra los dos backends. Es el antidoto de `Riesgo - el fake miente`.

Como se elige el backend
------------------------
La fixture `firewall` esta parametrizada con `pytest_generate_tests` e `indirect`,
y el parametro `iptables` lleva el marcador `requires_iptables`. Consecuencia:

    pytest                      -> solo el fake       (Mac y VM; addopts lo excluye)
    pytest -m requires_iptables -> solo iptables real  (dentro de la VM)

Se parametriza con `metafunc.parametrize(..., marks=...)` y no poniendo los marks
en `@pytest.fixture(params=[...])` porque esta es la forma documentada y estable:
la suite entera depende de que ese marcador se aplique de verdad. Si no se
aplicara, la mitad real se ejecutaria tambien en el Mac -- donde no hay iptables
-- y saldria roja por el motivo equivocado.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.firewall.base import FirewallBackend
from app.firewall.fake import FakeFirewallBackend
from tests.contract.casos import PARAMETROS_DEL_BACKEND
from tests.iptables_real import backend_real


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Cada test que pida `firewall` se ejecuta una vez por backend."""
    if "firewall" in metafunc.fixturenames:
        metafunc.parametrize(
            "firewall",
            [
                pytest.param("fake", id="fake"),
                pytest.param("iptables", id="iptables", marks=pytest.mark.requires_iptables),
            ],
            indirect=True,
        )


@pytest.fixture
def firewall(request: pytest.FixtureRequest) -> Iterator[FirewallBackend]:
    """Backend limpio, sin scaffold, y desmontado pase lo que pase.

    Se entrega SIN `ensure_scaffold`: crear las cadenas es parte de lo que la
    suite comprueba, y una fixture que lo hiciera por su cuenta se llevaria por
    delante el primer test del contrato.

    El `teardown` de entrada no es paranoia: si una ejecucion anterior murio a
    mitad (un Ctrl-C durante un `apply`), las cadenas siguen en el kernel y el
    test siguiente empezaria sobre restos ajenos. Es idempotente por diseño.
    """
    if request.param == "fake":
        backend: FirewallBackend = FakeFirewallBackend(**PARAMETROS_DEL_BACKEND)
    else:
        backend = backend_real()

    backend.teardown()
    try:
        yield backend
    finally:
        backend.teardown()
