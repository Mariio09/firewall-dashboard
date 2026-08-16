"""El unico punto del proyecto que ejecuta procesos externos.

Bloque B2. Si `subprocess` aparece en cualquier otro archivo, es un bug de
seguridad, no de estilo.

Defensa en profundidad (docs/SECURITY.md):
  1. `shell=False` SIEMPRE. Es el valor por defecto de `subprocess.run`, pero se
     deja explicito porque es el punto entero del ejercicio: sin shell no hay
     interpretacion de `;`, `|`, `$()` ni comillas, asi que la inyeccion de
     comandos deja de ser posible por construccion.
  2. Allowlist de binarios. Un argv cuyo ejecutable no este en `ALLOWED_BINARIES`
     lanza `SecurityError` antes de llegar al sistema.
  3. Argumentos siempre en lista, nunca concatenando strings.
  4. Entorno minimo y `LC_ALL=C`, para que el parser no dependa del locale de la
     VM y no se hereden variables del proceso padre.
  5. Timeout obligatorio: un `iptables` esperando el lock del xtables bloquea el
     worker indefinidamente.
  6. Log estructurado del argv completo ANTES de ejecutar.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

DEFAULT_TIMEOUT_SECONDS = 10.0

#: Entorno minimo. `LC_ALL=C` fija el formato de salida de iptables.
SAFE_ENV: dict[str, str] = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}

#: Unicos ejecutables que este proyecto puede invocar, jamas ampliar sin ADR.
ALLOWED_BINARIES: frozenset[str] = frozenset(
    {"iptables", "ip6tables", "iptables-save", "iptables-restore"}
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float


class CommandRunner(Protocol):
    """Costura de test mas interna.

    Inyectando un runner falso que devuelve stdout enlatado se puede verificar que
    `IptablesBackend` construye el argv correcto y que el parser lee bien salidas
    reales, todo sin ejecutar nada. Ver docs/ARCHITECTURE.md §3.4.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        check: bool = True,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Implementacion real. Solo se instancia dentro de la VM.

    TODO(B2): implementar siguiendo la lista de defensas del docstring del modulo.
    El primer test a escribir es el que verifica que un binario fuera de la
    allowlist lanza `SecurityError`.
    """

    def __init__(self, *, use_sudo: bool = True, iptables_bin: str = "/usr/sbin/iptables") -> None:
        self._use_sudo = use_sudo
        self._iptables_bin = iptables_bin

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        check: bool = True,
    ) -> CommandResult:
        raise NotImplementedError("TODO(B2)")
