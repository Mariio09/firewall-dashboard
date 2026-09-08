# Runbook — qué hacer cuando algo va mal

> Léelo **antes** de aplicar tu primera regla real, no después.

---

## Lo primero que hay que saber

> **Corrección de B4 (2026-09-04).** Hasta esta fecha, este runbook empezaba
> diciendo que `multipass shell` no pasa por TCP y que por eso sigue funcionando
> aunque cierres la red. **Es falso, y estaba escrito en el sitio donde más caro
> sale equivocarse.** Se midió con `make b4-probe`.

**`multipass shell` y `multipass exec` entran por SSH, por la red de la VM.**

La cadena de procesos dentro de la VM lo dice sin ambigüedad:

```
bash(8274) <- sudo(8273) <- sshd(8272) <- sshd(8225) <- sshd(2290) <- systemd(1)
```

y el otro extremo de la conexión al puerto 22 es `192.168.252.1`, que es el host.
No hay vsock, ni puertos virtio, ni agente del hipervisor: hay un `authorized_keys`
con la clave de multipassd. **Un `DROP` que alcance al puerto 22 cierra también la
puerta de emergencia.**

### Lo que sí te saca de un bloqueo

1. **Una sesión abierta ANTES de aplicar.** El guardián de conntrack
   (`RELATED,ESTABLISHED`, primera regla de las tres cadenas) mantiene viva una
   conexión ya establecida; lo que se pierde es la capacidad de abrir una nueva.
   Por eso: **abre `multipass shell firewall-lab` en otra terminal antes de tocar
   nada.** No es una recomendación de estilo, es la diferencia entre volver o no.

   **Medido en B4** (`make b4-verify FASE=ssh`, 2026-09-04): con un `DROP` del 22
   aplicado, una sesión nueva no entra y **2 conexiones ya establecidas siguieron
   vivas**. Y ojo al detalle que hace este caso traicionero: **la API seguía
   respondiendo con normalidad**. Cortar el 22 no toca el 8000, así que el
   dashboard se ve perfecto desde el navegador mientras tú te has quedado fuera de
   la máquina.
2. **Reiniciar la VM.** `iptables` vive en memoria y en esta VM no hay nada que lo
   restaure al arrancar: `ufw` está habilitado como unidad pero **inactivo**, y no
   hay `iptables-persistent`. Compruébalo antes de confiar en ello:
   `make b4-probe` lo mide en la sección V4.
   ⚠️ Con `FIREWALL_BACKEND=iptables` y `AUTO_APPLY=true`, el servicio arranca
   solo y puede volver a aplicar la política que te dejó fuera. Párale primero:
   `systemctl disable --now firewall-dashboard`.
3. **Snapshots.** `multipass snapshot` existe desde 1.13 (aquí, 1.16.3) y no
   depende de la red de la VM. Requiere la VM parada.

### Lo que aún no está medido

Que `multipass stop --force` funcione con el 22 cortado es **plausible pero no
comprobado**: el apagado limpio puede ir por SSH. Hasta que se mida, no cuenta
como vía de escape. Distinguir lo medido de lo supuesto es la lección entera de
este bloque.

---

## Emergencia 1 — Me he bloqueado el acceso a la VM

**Síntomas:** el dashboard no carga, `curl` a la API da timeout, `ssh` no conecta.

```bash
# 1. Entrar. Si tienes una sesion ya abierta, USA ESA: una nueva puede no entrar
#    (ver arriba: multipass va por SSH, y el 22 puede estar cortado)
multipass shell firewall-lab

# 2. Ver qué has hecho
sudo iptables -S

# 3. Reset controlado: elimina solo lo de la aplicación
sudo bash /home/ubuntu/app/infra/scripts/panic_reset.sh
```

Desde el host, en una línea: `make panic`.

`panic_reset.sh` es quirúrgico: quita los saltos a `FWDASH_*`, vacía y borra esas
cadenas, y pone las políticas por defecto en `ACCEPT`. **No** toca reglas que no
sean de la aplicación (Docker, ufw), que es justo la ventaja de haber usado cadenas
propias.

---

## Emergencia 2 — La API responde pero el dashboard no recibe nada

**Síntomas:** las peticiones llegan al backend (se ven en los logs) pero el
navegador da timeout.

Este es el auto-bloqueo por `OUTPUT`, y es el más confuso de todos porque desde
fuera parece un problema de red genérico. Has creado una regla que filtra tráfico
**saliente** y ha cortado las respuestas de la propia API.

```bash
multipass shell firewall-lab
sudo iptables -S FWDASH_OUTPUT          # busca DROP/REJECT sospechosos
sudo iptables -F FWDASH_OUTPUT          # vacía solo esa cadena
```

Si esto ocurre, comprueba también que las reglas guardián de `OUTPUT` se están
emitiendo: debe haber un `ACCEPT` de `ESTABLISHED,RELATED` en la primera posición.
Si no está, es un bug del renderer, no un error de uso.

---

## Emergencia 2-bis — No puedo abrir NINGUNA sesión

**Síntomas:** `multipass shell` y `multipass exec` se quedan colgados o dan
timeout. Es el caso que el runbook viejo daba por imposible.

Por orden, de menos a más destructivo:

```bash
# 1. ¿Tienes una sesión abierta de antes? Úsala. El guardián de conntrack la
#    mantiene viva aunque el 22 esté cerrado a cal y canto.
sudo bash /opt/firewall-dashboard/infra/scripts/panic_reset.sh

# 2. Si no la tienes: reiniciar. iptables no persiste (compruébalo con
#    'make b4-probe' antes de necesitarlo).
multipass stop firewall-lab && multipass start firewall-lab

# 3. Y en cuanto entres, ANTES de que el servicio reaplique la política.
#    Desde C2 esto es LITERAL: el servicio reconcilia la politica al arrancar
#    (ADR-0018), asi que reiniciar la VM NO te libra de una politica que te deja
#    fuera -- vuelve a aplicarse sola en cuanto systemd levanta el servicio.
#    Tienes la ventana entre que arranca la VM y arranca el servicio; si la
#    pierdes, repite el reinicio y ve mas rapido, o entra por 'multipass shell'
#    con el servicio ya caido por el bloqueo.
sudo systemctl disable --now firewall-dashboard

# 4. Snapshot previo, si lo hiciste:
multipass restore firewall-lab.<nombre>
```

**La lección para la próxima vez** está en `infra/scripts/b4_bloqueo.sh`: arma la
reversión **antes** de aplicar, no después. Un `systemd-run --on-active=90` que
ejecute `panic_reset.sh` convierte "me he bloqueado" en "estuve bloqueado noventa
segundos". Es el patrón de `iptables-apply`, y `make b4-verify` lo ejercita entero.

---

## Emergencia 3 — La base de datos y iptables no coinciden (drift)

**Síntomas:** la UI muestra un aviso de drift; `sync_state` en `drift`.

Alguien (probablemente tú, a mano) modificó `iptables` por fuera de la aplicación.
La base de datos es la fuente de verdad, así que la resolución es reimponerla:

```bash
curl -X POST http://<ip-vm>:8000/api/v1/firewall/apply \
     -H "Authorization: Bearer <token>"
```

Si prefieres quedarte con lo que hay en el sistema, primero míralo:

```bash
sudo iptables -S FWDASH_INPUT
```

y recrea a mano en la UI las reglas que quieras conservar. **No hay importación
automática** de iptables a la base de datos, y es deliberado: importar reglas
arbitrarias significaría parsear todo lo que iptables permite expresar, que es
mucho más de lo que este modelo de datos representa.

---

## Emergencia 4 — La aplicación no arranca

```bash
# ¿Qué dice el servicio?
systemctl status firewall-dashboard --no-pager
journalctl -u firewall-dashboard -n 50 --no-pager

# ¿Falta una variable obligatoria?
cd /opt/firewall-dashboard/backend
set -a; . /etc/firewall-dashboard/backend.env; set +a
.venv/bin/python -c "from app.core.config import get_settings; print(get_settings())"

# ¿Migraciones pendientes?
runuser -u fwdash -- .venv/bin/alembic current

# ¿Los privilegios están donde crees? El arnés lo dice entero:
sudo bash /opt/firewall-dashboard/infra/scripts/b1_verify.sh
```

**Errores de arranque que ya han pasado, y qué significan:**

| Síntoma | Causa |
|---|---|
| `status=203/EXEC` | el `ExecStart` no existe *dentro del namespace*. Casi siempre, una ruta bajo `/home` con `ProtectHome=yes` (ADR-0014), o el bit de ejecución perdido en el venv |
| `status=200/CHDIR` | el `WorkingDirectory` no es alcanzable para `fwdash` |
| `Permission denied` al escribir la DB | `firewall.db` es de root: se migró como root en vez de como `fwdash` |
| `sudo: a password is required` | `USE_SUDO=true` con la unidad instalada. `NoNewPrivileges=yes` anula el setuid de `sudo`: pon `USE_SUDO=false` (ADR-0003) |
| el valor de una variable trae un comentario pegado | comentario al final de una línea en `/etc/firewall-dashboard/backend.env`: systemd se queda con la línea entera |
| arranca pero el firewall esta vacio, y el journal dice `reconciliacion_de_arranque_fallida` | la aplicacion arranco y la reconciliacion de C2 fallo (ADR-0015 y ADR-0018): el motivo va en esa misma linea del log, y las reglas afectadas estan en `sync_state=failed` con su `last_error`. La aplicacion NO se cae por esto, a proposito: `/firewall/status` es lo que hay que mirar |
| `iptables: Incompatible with this kernel.` | **la cadena no existe.** Medido en B4 con `iptables v1.8.10 (nf_tables)`: un `-L FWDASH_INPUT` sobre una cadena que no está devuelve ese mensaje, no `No chain/target/match by that name`. No es un problema de kernel ni de módulos: falta `ensure_scaffold()`. Compruébalo creándola (`sudo iptables -N FWDASH_INPUT`) y repitiendo el `-L` |

Si falla por falta de `JWT_SECRET_KEY`, es intencionado: la aplicación se niega a
arrancar sin secreto en lugar de generar uno al vuelo y darte una falsa sensación
de seguridad.

---

## Emergencia 5 — He commiteado un secreto

No basta con borrarlo en el commit siguiente: sigue en el historial.

1. **Rota el secreto inmediatamente.** Genera uno nuevo
   (`openssl rand -hex 32`). Esto es lo urgente; el resto es limpieza.
2. Reescribe el historial con `git filter-repo` (o BFG).
3. Si el repositorio ya está en GitHub, considéralo comprometido aunque sea
   privado.
4. Instala `pre-commit` para que no vuelva a pasar: el hook de `gitleaks` ya está
   configurado.

---

## Copias de seguridad antes de tocar nada

```bash
# Estado completo de iptables, con fecha
sudo iptables-save > ~/iptables-backup-$(date +%Y%m%d-%H%M%S).rules

# Restaurar
sudo iptables-restore < ~/iptables-backup-XXXXXX.rules

# Base de datos
cp /var/lib/firewall-dashboard/firewall.db ~/firewall-backup-$(date +%Y%m%d).db
```

Los `.rules` están en `.gitignore` por algo: un `iptables-save` es un mapa de tu
red.

---

## Reinicio limpio total

Si todo está tan roto que no merece la pena diagnosticar:

```bash
make vm-provision                 # destruye, recrea y verifica la VM entera
make vm-clone && make vm-deploy    # el codigo dentro, y desplegado en /opt
```

Son dos minutos. Es una VM de laboratorio: destruirla y recrearla es una
herramienta legítima, no una derrota.

---

## Antes de aplicar tu primera política real

Una lista corta, toda ella salida de B4:

- [ ] `multipass shell firewall-lab` abierto en otra terminal, **antes** de aplicar.
- [ ] `sudo iptables-save > ~/iptables-backup-$(date +%Y%m%d-%H%M%S).rules` en la VM.
- [ ] `MANAGEMENT_ALLOWED_CIDR` **consultado, no supuesto**:
      `multipass exec firewall-lab -- ip -4 -o addr show scope global` (ADR-0016).
- [ ] `MANAGEMENT_SSH_PORT` declarado en el `.env` de la VM (ADR-0017), o saber que el
      guardián protege el puerto de gestión **y solo ese**: sin declararlo, el 22 —por donde
      entra multipass— no lo protege nadie. Compruébalo, no lo supongas:
      `sudo grep ^MANAGEMENT_SSH_PORT /etc/firewall-dashboard/backend.env`
- [ ] `GET /firewall/preview` leído: enseña el argv exacto sin ejecutarlo.
- [ ] `FIREWALL_BACKEND` sabido, no supuesto. Con `fake` no pasa nada de esto y con
      `iptables` pasa todo: `sudo grep ^FIREWALL_BACKEND /etc/firewall-dashboard/backend.env`.
      Y recuerda que desde C2 el servicio **aplica solo al arrancar** (ADR-0018): el
      momento peligroso ya no es únicamente cuando pulsas *aplicar*, también es cada
      `systemctl restart`.
