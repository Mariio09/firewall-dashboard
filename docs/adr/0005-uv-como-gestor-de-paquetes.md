# ADR-0005: Usar `uv` como gestor de paquetes

- **Fecha:** 2026-08-16
- **Estado:** Aceptado

## Contexto

`python -m venv` no funciona en la máquina de desarrollo (macOS, Apple Silicon).
`ensurepip` falla siempre, con el mismo error:

```
truststore/_macos.py, line 22
    _mac_version_info = tuple(map(int, _mac_version.split(".")))
ValueError: invalid literal for int() with base 10: ''
```

`platform.mac_ver()` devuelve cadena vacía en esta máquina; `truststore`, vendorizado
dentro de pip, intenta convertir esa cadena a enteros y revienta **durante el import**.
Como el fallo ocurre al importar, pip no lo captura y muere entero: rompe por igual
`python -m venv`, `ensurepip` y `get-pip.py`, porque los tres pasan por el mismo pip.

No es una preferencia de herramienta: sin resolverlo no hay entorno en el que instalar
el proyecto.

## Opciones consideradas

### A — Arreglar la causa raíz
Averiguar por qué `mac_ver()` devuelve vacío y corregirlo.
**Ventajas:** deja la máquina en un estado sano y no añade herramientas.
**Inconvenientes:** tiempo indefinido en un problema que no es el proyecto, y sin
garantía de solución. El diagnóstico sigue pendiente como deuda técnica, pero no puede
bloquear el arranque.

### B — Instalar pip por otra vía (Homebrew, `pipx`, `--system-site-packages`)
**Ventajas:** no cambia el flujo habitual.
**Inconvenientes:** todos los caminos acaban ejecutando el mismo pip roto, o dependen
de un Python del sistema que no se controla.

### C — `uv`
Gestor de paquetes y de entornos que no pasa por `ensurepip` y que además descarga y
gestiona su propio CPython.
**Ventajas:** esquiva el fallo por completo; instala en segundos; el `.venv` que
produce es un venv estándar.
**Inconvenientes:** una herramienta más que hay que tener instalada, y un CPython que
no es ni el del sistema ni el de Homebrew.

## Decisión

**Opción C**, con `venv + pip` como alternativa automática:

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
```

`make install` detecta si `uv` está disponible y lo usa; si no, cae al camino clásico.
Así el repositorio sigue siendo instalable en una máquina sana sin `uv`, que es lo que
importa para cualquiera que lo clone.

## Consecuencias

**Positivas:** el `.venv` resultante es estándar, así que `make test`, `make lint` y
`make dev-backend` funcionan sin cambios y sin saber nada de `uv`. La instalación pasa
de fallar a tardar segundos.

**Negativas:** el entorno usa el CPython que gestiona `uv`
(`~/.local/share/uv/python/cpython-3.12-macos-aarch64-none`) y no el de Homebrew, así
que un `python3` suelto en la terminal no es el mismo intérprete que el del proyecto.
Y la causa raíz sigue sin diagnosticar: el problema está esquivado, no resuelto.

**Qué invalidaría esta decisión:** que `python -m venv` volviera a funcionar en la
máquina (por una actualización de macOS o de pip). Aun así, `uv` se quedaría por
velocidad; lo que cambiaría es que dejaría de ser obligatorio.
