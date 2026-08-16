# Runbook — qué hacer cuando algo va mal

> Léelo **antes** de aplicar tu primera regla real, no después.

---

## Lo primero que hay que saber

**`multipass shell firewall-lab` no pasa por TCP.**

Usa el canal de control del hipervisor, no la red de la VM. Eso significa que
sigue funcionando aunque hayas cerrado el firewall a cal y canto y no puedas hacer
ni ping. Es tu vía de escape fuera de banda, y es la razón por la que este proyecto
es seguro de romper.

Si te bloqueas: no entres en pánico, abre una shell y ejecuta el reset.

---

## Emergencia 1 — Me he bloqueado el acceso a la VM

**Síntomas:** el dashboard no carga, `curl` a la API da timeout, `ssh` no conecta.

```bash
# 1. Entrar por el canal fuera de banda
multipass shell firewall-lab

# 2. Ver qué has hecho
sudo iptables -S

# 3. Reset controlado: elimina solo lo de la aplicación
sudo bash /home/ubuntu/app/infra/scripts/panic_reset.sh
```

Desde el Mac, en una línea: `make panic`.

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
# ¿Falta una variable obligatoria?
cd /home/ubuntu/app/backend && python -c "from app.core.config import get_settings; print(get_settings())"

# ¿Migraciones pendientes?
alembic current && alembic upgrade head

# ¿Permisos de iptables?
sudo -u fwdash /usr/sbin/iptables -S      # opción A (sudoers)
systemctl status firewall-dashboard        # opción B (capabilities)
```

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
multipass delete firewall-lab && multipass purge
make vm-create && make vm-mount
```

Son dos minutos. Es una VM de laboratorio: destruirla y recrearla es una
herramienta legítima, no una derrota.
