"""Configuracion de structlog para el logging de la APLICACION.

Bloque A1. No confundir con `packet_logs`, que son los paquetes bloqueados por
iptables (fase 2). Aqui va telemetria: request_id, comandos ejecutados, errores.

Requisito de seguridad: un processor debe censurar por NOMBRE de clave
(password, token, secret, authorization). Ver docs/ARCHITECTURE.md §5.3."""
