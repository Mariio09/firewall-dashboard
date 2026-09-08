"""Capa de abstraccion sobre iptables.

ESTE ES EL UNICO PAQUETE DEL REPOSITORIO QUE EJECUTA `subprocess`.

Reglas que sostienen el diseño (docs/ARCHITECTURE.md §3):

1. Este paquete NO conoce la base de datos, ni FastAPI, ni Pydantic. Recibe y
   devuelve dataclasses puras. Es lo que lo hace testeable sin infraestructura.
2. Toda la validacion de entrada de red vive en `validators.py`. Ningun otro
   modulo del proyecto tiene permiso para interpretar una IP o un puerto.
3. `RuleSpec` es inmutable y se valida al construirse: no se puede fabricar una
   spec invalida. La validacion no esta centralizada "por convencion", esta en el
   unico sitio por el que es posible pasar.
4. Solo hay UNA operacion de escritura, `apply_ruleset()`. No hay add/delete.
   El estado final depende solo de la DB (ADR-0002).

Bloques: `spec`, `validators`, `renderer`, `parser`, `base` y `fake` son del
bloque A (se construyen y testean en el host). `runner` e `iptables` son del
bloque B (tocan el sistema).
"""
