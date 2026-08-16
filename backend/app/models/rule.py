"""Modelo `Rule`: la entidad central del proyecto.

Bloque A1. La DB es la fuente de verdad; iptables la refleja (ADR-0001).
Campos sensibles al diseño, ver docs/ARCHITECTURE.md §2.2:
  - `uuid`      identificador publico y etiqueta de la regla en iptables
  - `position`  el orden ES la semantica en iptables; unico por cadena
  - `sync_state`  pending | applied | failed | drift
  - `src_ip`    texto normalizado a CIDR por el validador, nunca crudo
  - `src_port`  str, no int: '80' y '8000:8010' son ambos validos"""
