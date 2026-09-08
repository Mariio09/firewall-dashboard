# ADR-0001: La base de datos es la fuente de verdad de las reglas

- **Fecha:** 2026-08-16
- **Estado:** Aceptado

## Contexto

Una regla de firewall puede vivir en dos sitios: en la tabla de iptables del
kernel, o en una base de datos de la aplicación. Hay que decidir cuál manda,
porque de eso depende qué hace `GET /rules`, qué ocurre al reiniciar la VM y si
las reglas pueden llevar metadatos.

iptables no permite adjuntar información arbitraria a una regla. Lo más parecido es
el módulo `comment`, limitado a 256 caracteres y sin estructura.

## Opciones consideradas

### A — iptables como fuente de verdad
Cada listado parsea `iptables -L -v -n` en tiempo real.
**Ventajas:** siempre refleja la realidad; imposible que haya divergencia.
**Inconvenientes:** no hay sitio donde guardar quién creó la regla, cuándo ni por
qué; se pierde todo al reiniciar salvo `iptables-persistent`; el listado depende de
ejecutar un comando privilegiado.

### B — La base de datos como fuente de verdad
SQLite guarda las reglas gestionadas con metadatos; iptables es un reflejo que se
reconstruye.
**Ventajas:** metadatos, historial y auditoría; persistencia entre reinicios;
listar no requiere privilegios; el drift se convierte en información útil.
**Inconvenientes:** dos estados que pueden divergir; hay que implementar
reconciliación y detección de drift.

### C — Híbrido con etiquetas en comentarios
iptables manda, pero cada regla lleva `-m comment --comment "fwdash:<uuid>"`.
**Ventajas:** identificación estable sin base de datos.
**Inconvenientes:** los metadatos siguen sin caber; parsear comentarios como
almacén de datos es frágil.

## Decisión

**Opción B.**

El proyecto no es "una interfaz web para iptables", es una herramienta de gestión
de política de firewall. La diferencia está justamente en los metadatos: el campo
`description` que explica *por qué* existe una regla, el `created_by` que dice
quién la puso, el `audit_events` que registra el cambio. Nada de eso cabe en
iptables.

La divergencia, que es el inconveniente real de esta opción, se convierte en una
funcionalidad: `sync_state` la hace visible en la interfaz y `GET /firewall/status`
la reporta. Un firewall que te avisa de que alguien lo tocó por fuera es más útil
que uno que no puede saberlo.

## Consecuencias

**Positivas:** metadatos, auditoría y persistencia; el frontend funciona sin
privilegios; el bloque A (todo el MVP en el host contra un backend falso) es
posible precisamente porque la verdad vive en la base de datos.

**Negativas:** hay que escribir reconciliación y detección de drift, que no
existirían con la opción A. Una regla puede estar en la base de datos y no
aplicada, lo que hay que comunicar bien en la interfaz o confunde.

**Qué invalidaría esta decisión:** que apareciera la necesidad de gestionar reglas
preexistentes creadas por otras herramientas. Importar iptables arbitrario a este
modelo de datos no es viable, y ahí la opción C sería mejor.
