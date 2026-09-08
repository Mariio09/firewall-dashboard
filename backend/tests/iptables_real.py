"""Como se construye el backend REAL en los tests. En un solo sitio, a proposito.

Lo usan la suite de contrato (mitad `iptables`) y la de `e2e_vm`. Si cada una lo
montara por su cuenta, acabarian probando dos configuraciones distintas y la
comparacion entre ellas dejaria de significar nada.

Nada de este modulo se importa en el host: las funciones traen dentro el import de
`SubprocessRunner`, que es el unico modulo del proyecto que carga `subprocess`.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import pytest

from tests.contract.casos import PARAMETROS_DEL_BACKEND, PREFIJO_DE_PRUEBA

if TYPE_CHECKING:
    from app.firewall.iptables import IptablesBackend
    from app.firewall.runner import CommandRunner

__all__ = ["backend_real", "exigir_iptables_vivo", "runner_real"]


def runner_real() -> CommandRunner:
    """El runner de verdad, con la misma allowlist que usa el servicio.

    `use_sudo` se decide por el euid REAL del proceso y no por una variable de
    entorno: si la suite corre bajo `sudo`, anteponer `sudo` otra vez seria pedir
    privilegios que ya se tienen; y si no corre como root, hacen falta. Preguntar
    por el hecho en vez de configurarlo cierra el unico modo de fallo interesante
    aqui, que es creerse root sin serlo.
    """
    from app.firewall.runner import SubprocessRunner

    return SubprocessRunner(
        use_sudo=os.geteuid() != 0,
        iptables_bin=os.environ.get("IPTABLES_BIN", "/usr/sbin/iptables"),
    )


def exigir_iptables_vivo(runner: CommandRunner) -> None:
    """Si iptables no responde, esto es ROJO. Nunca un `skip`.

    Es la leccion mas cara de B4: un arnes que se salta lo que no puede medir
    acaba en verde sobre un sistema donde no se ejecuto nada. Un `skip` aqui
    diria "todo bien" con el firewall muerto, que es justo el fallo que estas
    suites existen para detectar. Quien decide DONDE corren es el marcador
    `requires_iptables`; una vez dentro, no hay excusa que valga.

    Y se comprueba que la salida no venga vacia, no solo el codigo de retorno:
    `iptables -S` sin una sola linea es un sistema que no ha contestado, aunque
    haya devuelto 0.
    """
    resultado = runner.run(["iptables", "-S"], check=False)
    if not resultado.ok or not resultado.stdout.strip():
        pytest.fail(
            f"iptables no responde en esta maquina (codigo {resultado.returncode}): "
            f"{resultado.stderr.strip()[:200]!r}. Estos tests solo tienen sentido "
            "dentro de la VM y con privilegios: make test-vm."
        )


def backend_real(**extra: Any) -> IptablesBackend:
    """`IptablesBackend` con los parametros compartidos y iptables comprobado.

    El prefijo NO puede ser el del despliegue: estas pruebas hacen `-F` y `-X`
    sobre las cadenas que crean, y compartir nombre con el servicio significaria
    llevarse por delante la politica real en el primer test que muriera a mitad.
    """
    from app.firewall.iptables import IptablesBackend

    assert PREFIJO_DE_PRUEBA != "FWDASH", "las pruebas no tocan las cadenas del despliegue"

    runner = runner_real()
    exigir_iptables_vivo(runner)
    return IptablesBackend(runner, **{**PARAMETROS_DEL_BACKEND, **extra})
