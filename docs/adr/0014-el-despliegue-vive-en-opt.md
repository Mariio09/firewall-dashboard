# ADR-0014 — El código que ejecuta el servicio vive en `/opt`, no en el home

- **Fecha:** 2026-09-03
- **Estado:** Aceptado

## Contexto

El [ADR-0013](0013-el-codigo-entra-en-la-vm-clonado.md) dejó el repositorio
clonado en `/home/ubuntu/app` dentro de la VM. El [ADR-0003](0003-privilegios-sudo-vs-capabilities.md)
eligió `CAP_NET_ADMIN` vía systemd como forma de darle privilegios al backend, con
un usuario de servicio `fwdash` sin login. Al llegar a B1 e intentar arrancar el
servicio, las dos decisiones chocaron.

La unidad apuntaba a `/home/ubuntu/app` y **no podía arrancar**, por dos motivos
que son independientes entre sí — arreglar uno no arregla el otro:

1. **Permisos.** En Ubuntu 24.04 el home de un usuario se crea `0750`. `fwdash`
   es un usuario de sistema sin grupo común con `ubuntu`: no puede ni *atravesar*
   `/home/ubuntu`, así que el venv, el código y el `.env` eran ilegibles para él.
2. **El propio sandbox.** La unidad lleva `ProtectHome=yes`, que oculta `/home`
   entero dentro del namespace del servicio. Aunque los permisos fuesen
   correctos, el `ExecStart` no existiría para el proceso (`status=203/EXEC`).
   Tener a la vez `ProtectHome=yes` y `ReadOnlyPaths=/home/ubuntu/app` era una
   contradicción escrita en el mismo archivo.

Un tercer problema, más silencioso: el `EnvironmentFile` apuntaba a
`backend/.env`, es decir, el `JWT_SECRET_KEY` de la VM vivía **dentro del árbol
del repositorio**, que es justo el sitio donde un `git add -A` distraído lo
encuentra.

## Opciones consideradas

### A — Abrir el home
`chmod 0755 /home/ubuntu` y `ProtectHome=read-only` en la unidad. Cero trabajo de
despliegue: el servicio ejecuta el mismo árbol que se sincroniza con `make vm-sync`.
A cambio, una unidad endurecida que tiene que abrir precisamente lo que endurece,
y el secreto sigue dentro del repo. Además `ProtectHome=read-only` expone al
servicio el home entero del usuario, no solo la aplicación.

### B — Clonar directamente a `/srv`
Cambiar el destino de `vm-clone`/`vm-sync` a `/srv/firewall-dashboard`, propiedad
de `ubuntu:fwdash`. Un solo árbol, sin paso de copia. Obliga a tocar el ADR-0013
y mezcla en un mismo directorio el área de trabajo (con `.git`, cambios sin
commitear y artefactos de test) y lo que ejecuta un proceso privilegiado.

### C — Separar área de trabajo y despliegue
El clon se queda en `/home/ubuntu/app`, que es de `ubuntu` y sirve para trastear.
Un paso de despliegue copia a `/opt/firewall-dashboard` (root:root, 0755) **solo
lo commiteado**, con su propio venv, y la configuración se va a
`/etc/firewall-dashboard/backend.env` (`0640 root:fwdash`).

## Decisión

**Opción C.** El servicio ejecuta `/opt/firewall-dashboard`, se configura desde
`/etc/firewall-dashboard/backend.env` y escribe únicamente en
`/var/lib/firewall-dashboard`. Lo hace `infra/scripts/deploy_vm.sh`, idempotente,
que se lanza después de cada `make vm-sync`.

El motivo no es el FHS por el FHS. Es que **un proceso privilegiado no debe
ejecutar un árbol de archivos donde alguien está editando**. Con el clon montado
en `/opt` bastaría un guardado a medias, un `git checkout` de otra rama o un
archivo de test para cambiar lo que corre con `CAP_NET_ADMIN`. Con la copia, lo
que se ejecuta es un commit concreto —`/opt/firewall-dashboard/.desplegado` dice
cuál— y el `rsync --delete` hace que no queden restos del despliegue anterior.

Como efecto lateral, la separación arregla el tercer problema sin esfuerzo: el
secreto vive en `/etc`, fuera del repositorio, legible solo por `root` y `fwdash`.

## Consecuencias

**Positivas:**

- `ProtectHome=yes` se queda intacto, y con él el resto del endurecimiento.
- Lo que corre es un commit identificable, no "lo que hubiera en el directorio".
- El secreto sale del árbol del repo.
- El venv de despliegue es de `root` y el servicio solo lo lee: ni siquiera un
  fallo en la aplicación puede reescribir su propio intérprete.

**Negativas:**

- **Un paso más en cada iteración.** Ya no basta `make vm-sync`: hay que
  `make vm-deploy` detrás. Editar y ver el cambio pasa por commit → sync →
  deploy, que es lento cuando se está depurando.
- Dos copias del código dentro de la VM. Si alguien edita `/opt` a mano, el
  siguiente despliegue se lo lleva por delante sin avisar.
- `deploy_vm.sh` es código de infraestructura nuevo que hay que mantener.

**Qué invalidaría esta decisión:** que el backend dejara de necesitar privilegios
(entonces podría correr como `ubuntu` sobre el clon y sobraría todo esto), o que
el proyecto pasara a empaquetarse —un `.deb`, o un contenedor— y el despliegue lo
resolviera el empaquetado.

## Comprobación

`infra/scripts/b1_verify.sh` comprueba el **efecto**, no la existencia: que
`fwdash` lee de verdad el `main.py` desplegado, que **no** puede escribir en
`/opt`, que el commit desplegado coincide con el `HEAD` del clon, y que el
`.env` es `0640 root:fwdash`.

Relacionado: [ADR-0003](0003-privilegios-sudo-vs-capabilities.md) ·
[ADR-0013](0013-el-codigo-entra-en-la-vm-clonado.md) · `docs/SETUP_VM.md` §4.
