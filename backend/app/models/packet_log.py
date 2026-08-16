"""Modelo `PacketLog`: paquetes registrados por el target LOG de iptables.

FASE 2. La tabla se crea ya (para no migrar esquema despues) pero permanece
vacia durante el MVP.

Decision: `rule_uuid` va SIN foreign key. Un log es un hecho historico y debe
sobrevivir al borrado de la regla que lo genero. Ver docs/ARCHITECTURE.md §2.3."""
