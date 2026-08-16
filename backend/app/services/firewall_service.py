"""Reconciliacion DB -> iptables, deteccion de drift y dry-run.

Bloque A5. El corazon del diseño (ADR-0002): 'aplicar' significa siempre vaciar
la cadena gestionada y reconstruirla entera desde la DB, en orden. Idempotente.
Se itera sobre las tres cadenas (INPUT / OUTPUT / FORWARD) de forma independiente.

Este modulo tambien inyecta las REGLAS GUARDIAN en cabecera de cada cadena.
No estan en la DB y no se pueden desactivar por API. Ver docs/ARCHITECTURE.md §0."""
