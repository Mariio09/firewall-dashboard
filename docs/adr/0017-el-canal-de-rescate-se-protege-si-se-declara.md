# ADR-0017 — El canal de rescate se protege solo si se declara

- **Fecha:** 2026-09-04
- **Estado:** Aceptado

## Contexto

Las reglas guardián (`docs/ARCHITECTURE.md` §0) existen para que ninguna regla de usuario
pueda dejarte fuera. Cubren tres cosas: el tráfico ya establecido, el `loopback` y el
**puerto de gestión** desde `MANAGEMENT_ALLOWED_CIDR`.

B4 midió que eso no basta en esta máquina. `multipass shell` y `multipass exec` **entran por
SSH**, por la misma red que el firewall filtra: no hay canal fuera de banda. El árbol de
procesos de una sesión de multipass es `bash <- sudo <- sshd <- sshd <- sshd <- systemd`, y
el otro extremo de la conexión al 22 es el host.

Consecuencia: una regla de usuario tan trivial como `DROP tcp --dport 22` se aplica **sin una
sola queja** y se lleva por delante la única vía de rescate. Está medido, no supuesto —
`make b4-verify FASE=ssh`, 2026-09-04—: el `DROP` absorbió paquetes, una sesión nueva no
entró, dos conexiones ya establecidas sobrevivieron gracias al guardián de conntrack, y **la
API siguió respondiendo con normalidad**, que es lo que hace este fallo tan traicionero: el
dashboard se ve perfecto desde el navegador mientras tú te has quedado fuera de la máquina.

Es el único agujero conocido de la red de guardianes, y lo abre la propia UI del proyecto.

## Opciones consideradas

### A — Guardián fijo para el 22

El renderer emite siempre un `ACCEPT` del puerto 22, como emite el de gestión.

**Ventajas:** imposible cortarse el rescate; cero configuración.
**Inconvenientes:** el firewall queda con un agujero **permanente, no configurable y no
declarado por nadie**. En un proyecto de seguridad defensiva eso no se puede defender: una
excepción que el operador no ha pedido, no puede quitar y no aparece en ninguna variable de
entorno es exactamente lo que un auditor marca. Y presupone que el canal de rescate es SSH
en el 22, que es verdad **aquí** y no en general.

### B — No añadir nada: mitigación de procedimiento

Se queda como está y el `RUNBOOK` manda: sesión abierta antes de aplicar, reversión armada
antes del cambio.

**Ventajas:** cero código; el firewall filtra todo, sin excepciones.
**Inconvenientes:** la protección depende de que el operador se acuerde, y el fallo que
previene es de dos clics en la UI. Las reglas guardián existen precisamente porque "acuérdate
de no hacerlo" no es una mitigación.

### C — `MANAGEMENT_SSH_PORT` opcional, sin valor por defecto

Si se declara, el renderer emite un cuarto guardián que abre ese puerto **desde
`MANAGEMENT_ALLOWED_CIDR`**. Si no se declara, no se emite nada y el 22 se filtra como
cualquier otro puerto.

## Decisión

**C**, y por el mismo criterio con el que se cerró el [ADR-0016](0016-el-cidr-de-gestion-se-declara-no-se-supone.md):
**lo que puede dejarte fuera se declara, no se supone.**

Por qué C y no A: el agujero sigue existiendo cuando hace falta, pero deja de ser invisible.
Está escrito en el `.env`, sale en `GET /firewall/preview` antes de ejecutarse, y en
`iptables -S` lleva la etiqueta `fwdash:guardian:ssh`. Un agujero declarado es una decisión;
uno fijo es un defecto.

Por qué C y no B: el canal de rescate es la única regla cuya pérdida no se puede reparar
desde la propia aplicación. Todo lo demás se arregla reaplicando.

Detalles que forman parte de la decisión:

- **Se ata al mismo `MANAGEMENT_ALLOWED_CIDR`**, nunca a `0.0.0.0/0`. El canal de rescate es
  el del administrador; abrir SSH al mundo desde la propia aplicación sería peor que el
  problema que resuelve.
- **Se emite en `INPUT` (`--dport`) y en `OUTPUT` (`--sport`)**, por simetría con el guardián
  de gestión: la respuesta de una sesión establecida ya la cubre conntrack, y este cubre el
  caso en que conntrack no esté.
- **`FORWARD` no lo lleva.** Por ahí no pasa el tráfico dirigido a esta máquina: no hay sesión
  de rescate que proteger.
- **El valor por defecto sigue siendo "no protegerlo"**, así que esta decisión no cambia el
  comportamiento de nadie que no la pida. En la VM lo declara `deploy_vm.sh` con `22`, que es
  donde sí sabemos que el rescate entra por SSH.

## Consecuencias

**Positivas:** la regla que te deja sin máquina ya no se puede aplicar por accidente en la VM.
El guardián viaja por el mismo camino que los demás —renderer, fake, backend real y parser—,
así que el `preview` enseña lo que se va a ejecutar y la detección de *drift* lo reconoce como
guardián y no como regla huérfana.

**Negativas:** una variable más en el `.env`, y quien no la declare sigue igual de expuesto:
el `RUNBOOK` no se retira, se mantiene para ese caso. Si `MANAGEMENT_SSH_PORT` coincide con
`MANAGEMENT_PORT` se emiten dos guardianes que abren el mismo puerto — es redundante, no un
error, y no se detecta como tal. Y no protege de lo que no pasa por la cadena gestionada: si
la política por defecto de `INPUT` se pone en `DROP` desde fuera de la aplicación, este
guardián no interviene.

**Qué invalidaría esta decisión:** que la VM gane un canal de administración de verdad fuera
de banda (una consola serie que no dependa de la red), o que se implemente el *apply* con
confirmación y rollback automático (decisión abierta 3): con una reversión armada siempre, el
auto-bloqueo deja de ser irreversible y el guardián pasa a ser conveniencia en vez de red de
seguridad.
