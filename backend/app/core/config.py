"""Configuracion de la aplicacion via Pydantic Settings.

Bloque A1. Carga `.env`, valida tipos al arrancar y expone `get_settings()`
cacheado. Si falta una variable obligatoria, la app NO debe arrancar:
fallar en el arranque siempre es mejor que fallar en la primera peticion.

Variable clave: FIREWALL_BACKEND ('fake' | 'iptables'), el interruptor que
permite correr todo el bloque A en el Mac sin VM. Ver docs/ARCHITECTURE.md §4."""
