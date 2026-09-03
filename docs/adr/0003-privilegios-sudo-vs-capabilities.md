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

---

## Corrección de B1 (2026-09-03)

Al aplicar esta decisión aparecieron tres cosas que el ADR daba por hechas y no
lo eran. La decisión se mantiene; el fragmento de unidad de la opción B, no.

**1. La unidad del ejemplo no arrancaba.** Apuntaba a `/home/ubuntu/app` y a la
vez llevaba `ProtectHome=yes`, que oculta `/home` dentro del namespace del
servicio: el `ExecStart` no existe para el proceso (`203/EXEC`). Y aunque no lo
llevara, en Ubuntu 24.04 el home es `0750` y `fwdash` no puede ni atravesarlo.
El despliegue se movió a `/opt` → [ADR-0014](0014-el-despliegue-vive-en-opt.md).
La unidad real, con la corrección, es `infra/systemd/firewall-dashboard.service`.

**2. A y B no se apilan: son alternativas.** `NoNewPrivileges=yes` impide que un
binario setuid escale, y `sudo` es setuid. Bajo el servicio, `sudo` devuelve
`EPERM` aunque `/etc/sudoers.d/firewall-dashboard` esté instalado y sea válido.
De ahí que el entorno de la VM lleve `USE_SUDO=false`: no es una preferencia, es
la única opción coherente con la unidad. `USE_SUDO=true` sirve para lanzar el
backend **a mano** como `fwdash`, fuera de systemd, que es exactamente el
inconveniente que este ADR anotaba en sus consecuencias — la opción A lo resuelve.

**3. Lo que importa es `AmbientCapabilities`, no el bounding set.** El backend no
ejecuta `iptables`: lanza un **subproceso** que lo ejecuta. Las capabilities
ambientales sobreviven al `execve` y llegan al hijo; el bounding set solo marca el
techo de lo que se puede tener. Con `CapabilityBoundingSet` a solas, el proceso
arranca con el conjunto efectivo vacío y `iptables` responde *Permission denied*.
`infra/scripts/b1_verify.sh` lo demuestra en los dos sentidos: comprueba que un
`subprocess.run(['iptables','-S'])` lanzado desde Python funciona con las ambient,
y **falla** con solo el bounding set. Sin esa contraprueba, la comprobación
positiva no distinguiría entre "las capabilities funcionan" y "`iptables` era
permisivo".

También cambió un detalle menor: `ReadWritePaths=/var/lib/firewall-dashboard` se
sustituyó por `StateDirectory=firewall-dashboard`, que además crea el directorio
con el propietario correcto en cada arranque.
