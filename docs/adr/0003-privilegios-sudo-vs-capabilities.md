# ADR-0003: Capabilities en lugar de sudo para modificar iptables

- **Fecha:** 2026-08-16
- **Estado:** Aceptado

## Contexto

El backend necesita ejecutar `iptables`, que requiere privilegios de red del
kernel. Corre como servicio, sin usuario interactivo, así que no puede pedir
contraseña.

## Opciones consideradas

### A — `sudo` con `NOPASSWD` restringido por `Cmnd_Alias`

```
Cmnd_Alias FWDASH_CMDS = /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
fwdash ALL=(root) NOPASSWD: FWDASH_CMDS
```

**Ventajas:** conocido por todo el mundo; se configura en un minuto; funciona igual
en cualquier distribución.

**Inconvenientes, y son graves:** conceder `iptables` completo sin contraseña es en
la práctica equivalente a root. `iptables-restore` reescribe la política entera
desde stdin; targets como `NFQUEUE` o `TEE` redirigen tráfico a procesos
arbitrarios. `sudoers` restringe *qué binario* se invoca, no *qué hace*. Es un
privilegio **nombrado**, no acotado. Además, un error de sintaxis en
`/etc/sudoers.d/` puede dejar la máquina sin `sudo`.

### B — `CAP_NET_ADMIN` vía systemd

```ini
[Service]
User=fwdash
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/firewall-dashboard
```

**Ventajas:** concede exactamente la capacidad que `iptables` necesita y nada más.
El proceso nunca es root ni puede llegar a serlo (`NoNewPrivileges`). Se combina
con el resto del endurecimiento de systemd: sistema de archivos en solo lectura,
`/home` inaccesible, `/tmp` privado. No hay binario `sudo` en la ruta de ejecución,
así que desaparece toda una clase de vectores.

**Inconvenientes:** ata el despliegue a systemd; menos familiar; hay que entender
la diferencia entre capabilities ambientales y del bounding set.

### C — Binario envoltorio con setuid
**Descartada.** Escribir código setuid propio es una fuente clásica de
vulnerabilidades y no aporta nada sobre la opción B.

## Decisión

**Opción B como modo correcto**, con la A soportada mediante `USE_SUDO=true` para
desarrollo rápido.

El razonamiento es el principio de mínimo privilegio aplicado con literalidad: el
proceso necesita administrar la red, no ser root. `CAP_NET_ADMIN` expresa
exactamente eso. `sudo` expresa "puede ejecutar este programa como root", que es
una afirmación mucho más amplia de lo necesario.

Hay una segunda razón, específica de un proyecto de portfolio: la diferencia entre
A y B es precisamente el tipo de matiz que distingue a alguien que ha copiado un
tutorial de alguien que entiende el modelo de privilegios de Linux. Poder explicar
por qué `NOPASSWD: /usr/sbin/iptables` es prácticamente root vale más en una
entrevista que cualquier gráfica del dashboard.

## Consecuencias

**Positivas:** superficie de privilegio mínima y verificable
(`systemd-analyze security firewall-dashboard` la puntúa). El endurecimiento de
systemd viene incluido. Material de conversación técnica de primer nivel.

**Negativas:** el despliegue queda atado a systemd. Hay que mantener dos rutas de
código (`USE_SUDO`), lo que añade una rama que testear. En desarrollo dentro de la
VM, ejecutar el backend a mano requiere `sudo` o `setcap` sobre el intérprete, que
es incómodo.

**Qué invalidaría esta decisión:** desplegar en un entorno sin systemd
(un contenedor, por ejemplo), donde habría que usar el modelo de capabilities del
runtime correspondiente.
