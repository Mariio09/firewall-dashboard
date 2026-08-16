# ADR-0002: Cadenas propias `FWDASH_*` y reconstrucción idempotente

- **Fecha:** 2026-08-16
- **Estado:** Aceptado

## Contexto

Aceptado el ADR-0001, hay que decidir *cómo* se lleva el estado de la base de datos
a iptables. El orden de las reglas en iptables es semántica pura: la primera que
hace match gana. Cualquier estrategia tiene que tratar el orden como un dato de
primera clase.

Además, la VM puede tener reglas que no son nuestras (Docker crea las suyas, ufw
también) y romperlas sería inaceptable.

## Opciones consideradas

### A — Inserción incremental en las cadenas del sistema
`iptables -I INPUT <pos> ...` al crear, `-D` al borrar.
**Ventajas:** cada operación toca lo mínimo; rápido.
**Inconvenientes:** los índices se desplazan con cada cambio ajeno; un fallo a
medias deja estado inconsistente; hay que localizar la regla exacta para borrarla;
reordenar es una secuencia frágil de borrados e inserciones; se compite por el
espacio de `INPUT` con Docker y ufw.

### B — Cadenas propias + reconstrucción completa
Se crean `FWDASH_INPUT`, `FWDASH_OUTPUT` y `FWDASH_FORWARD` con un único salto
desde cada cadena del sistema. Aplicar = vaciar la cadena gestionada y reconstruirla
entera desde la base de datos.
**Ventajas:** idempotente; aislamiento total; el orden es un campo, no un índice;
el drift se detecta comparando una sola cadena; desinstalar es borrar el salto.
**Inconvenientes:** cada cambio reescribe toda la cadena; hay una ventana de
microsegundos con la cadena vacía.

### C — `iptables-restore` atómico
Se genera el ruleset completo y se aplica de una vez.
**Ventajas:** atómico de verdad, sin ventana vacía; más rápido con muchas reglas.
**Inconvenientes:** más complejo; requiere generar y parsear el formato de
`iptables-save`; más difícil de depurar cuando falla.

## Decisión

**Opción B**, con la C como evolución natural si el rendimiento llegara a importar.

La reconstrucción completa elimina toda una clase de bugs: si el estado final
depende únicamente de la base de datos, no existe la posibilidad de acumular
duplicados ni de quedar a medias. En un firewall doméstico con decenas de reglas,
el coste de reescribir la cadena entera es irrelevante frente a esa garantía.

El aislamiento en cadenas propias no es un detalle menor: es lo que hace que este
proyecto sea seguro de instalar en una VM que ya tiene Docker.

La ventana con la cadena vacía es real pero acotada: las reglas guardián se emiten
primero, y la política por defecto de la cadena del sistema sigue vigente durante
la reconstrucción.

## Consecuencias

**Positivas:** una sola operación de escritura en toda la capa de firewall
(`apply_ruleset`), lo que simplifica drásticamente el Protocol y su doble de
prueba. Reordenar es cambiar un entero. La fase 2 (targets `LOG` antes de cada
`DROP`) se vuelve trivial.

**Negativas:** el adaptador no expone `add_rule`/`delete_rule`, lo que sorprende al
leerlo por primera vez. Ventana de microsegundos con la cadena vacía. Reglas
creadas a mano dentro de `FWDASH_*` se pierden en la siguiente aplicación — es
intencionado, pero hay que documentarlo.

**Qué invalidaría esta decisión:** un volumen de reglas donde reescribir la cadena
entera se note (miles), o un requisito de cero ventana de vulnerabilidad. En ambos
casos, migrar a la opción C.
