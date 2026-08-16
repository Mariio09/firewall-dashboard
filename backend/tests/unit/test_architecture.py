"""Las reglas de arquitectura, ejecutables.

Un diagrama en un README se queda obsoleto en tres semanas. Estos tests fallan en
CI en el momento en que alguien (tu, dentro de dos meses) cruza una frontera que
el diseño no permite.

Son los primeros tests del proyecto a proposito: valen desde el commit inicial,
cuando todavia no hay ni una funcionalidad que probar.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


def _imported_modules(path: Path) -> set[str]:
    """Modulos de primer nivel importados por un archivo Python."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def _python_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if p.name != "__pycache__")


def _qualified_imports(path: Path) -> set[str]:
    """Nombres completos de los modulos importados, para inspeccionar `app.*`."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


# --------------------------------------------------------------------------- #
# La regla que mas importa: subprocess vive en un unico sitio
# --------------------------------------------------------------------------- #


def test_subprocess_solo_se_importa_en_el_runner(app_root: Path) -> None:
    """`subprocess` solo puede aparecer en `app/firewall/runner.py`.

    Esta es la contencion principal contra la inyeccion de comandos: si toda
    ejecucion de procesos pasa por un unico archivo, auditar ese archivo audita el
    proyecto entero. Ver docs/SECURITY.md.
    """
    permitido = app_root / "firewall" / "runner.py"
    infractores = [
        path.relative_to(app_root)
        for path in _python_files(app_root)
        if path != permitido and "subprocess" in _imported_modules(path)
    ]
    assert not infractores, (
        f"`subprocess` solo puede importarse en firewall/runner.py. Infractores: {infractores}"
    )


def test_no_hay_shell_true_en_el_proyecto(app_root: Path) -> None:
    """`shell=True` no debe aparecer nunca, en ningun archivo."""
    infractores = [
        path.relative_to(app_root)
        for path in _python_files(app_root)
        if "shell=True" in path.read_text(encoding="utf-8")
    ]
    assert not infractores, f"`shell=True` esta prohibido en este proyecto: {infractores}"


# --------------------------------------------------------------------------- #
# Direccion de las dependencias
# --------------------------------------------------------------------------- #


def test_los_servicios_no_conocen_fastapi(app_root: Path) -> None:
    """`services/` no puede importar `fastapi`.

    Si un servicio lanza `HTTPException` o depende de `Request`, deja de poder
    testearse sin levantar la aplicacion. Los servicios lanzan excepciones de
    dominio (`core/exceptions.py`) y `api/errors.py` las traduce a HTTP.
    """
    services = app_root / "services"
    infractores = [
        path.relative_to(app_root)
        for path in _python_files(services)
        if "fastapi" in _imported_modules(path)
    ]
    assert not infractores, f"services/ no puede importar fastapi: {infractores}"


def test_la_capa_firewall_es_independiente(app_root: Path) -> None:
    """`firewall/` no conoce ni la base de datos, ni la API, ni el ORM.

    Es lo que permite testear toda la logica de reglas con dataclasses puras, sin
    levantar una base de datos ni una aplicacion web.
    """
    firewall = app_root / "firewall"
    prohibidos = {"fastapi", "sqlalchemy", "pydantic", "alembic"}
    infractores: list[tuple[str, set[str]]] = []
    for path in _python_files(firewall):
        malos = prohibidos & _imported_modules(path)
        if malos:
            infractores.append((str(path.relative_to(app_root)), malos))
    assert not infractores, f"firewall/ debe ser independiente de infraestructura: {infractores}"


def test_los_routers_no_llaman_al_firewall_directamente(app_root: Path) -> None:
    """`api/` pasa siempre por `services/`; nunca importa `app.firewall` a mano.

    Excepcion legitima: `api/deps.py`, que es justamente quien construye el backend
    y lo inyecta.
    """
    api = app_root / "api"
    excepciones = {"deps.py"}
    infractores = [
        str(path.relative_to(app_root))
        for path in _python_files(api)
        if path.name not in excepciones
        and any(mod.startswith("app.firewall") for mod in _qualified_imports(path))
    ]
    assert not infractores, (
        f"Los routers deben pasar por services/, no importar firewall/ directamente: {infractores}"
    )


# --------------------------------------------------------------------------- #
# Salud del scaffolding
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "paquete",
    ["core", "db", "models", "schemas", "services", "firewall", "api", "workers"],
)
def test_existen_todos_los_paquetes(app_root: Path, paquete: str) -> None:
    """Cada capa del diseño existe como paquete Python importable."""
    directorio = app_root / paquete
    assert directorio.is_dir(), f"Falta el paquete app/{paquete}/"
    assert (directorio / "__init__.py").is_file(), f"Falta app/{paquete}/__init__.py"
