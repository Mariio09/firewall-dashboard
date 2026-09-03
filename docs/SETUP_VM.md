# Preparar la VM `firewall-lab`

> **Cuándo necesitas esto.** En el bloque A no hace falta: el backend corre en el
> Mac con `FIREWALL_BACKEND=fake`. Solo necesitas la VM en dos momentos: el paso
> **A2** (captura de fixtures, 20 minutos, solo lectura) y el **bloque B** completo.

---

## Requisitos

Multipass en macOS (Apple Silicon):

```bash
brew install --cask multipass
multipass version
```

---

## 1. Crear la VM

### La vía corta: `make vm-provision` (paso B0)

```bash
make vm-provision 2>&1 | tee b0-verify.log
```

Recrea la VM desde cero con el cloud-init del repo, la monta y **comprueba el
resultado**: que los paquetes están, que el `motd` y el directorio de datos se
escribieron, que `python3` es 3.11+, que `iptables` sigue siendo la misma
versión contra la que se escribió el parser, que la política nace virgen y que
el montaje es de lectura y escritura en los dos sentidos.

Es destructivo (`multipass delete --purge`) y **pide confirmación** antes de
borrar nada. Las fixtures de A2 ya están en el repo, así que no se pierde nada
del proyecto.

> **Por qué recrear en vez de reutilizar.** Un `cloud-init.yaml` que nunca se ha
> vuelto a ejecutar no es provisión reproducible, es un archivo que da la
> casualidad de que existe. B0 lo ejecuta de verdad.

### A mano

```bash
make vm-create
```

Equivale a:

```bash
multipass launch 24.04 --name firewall-lab --cpus 2 --memory 2G --disk 10G \
                 --cloud-init infra/cloud-init.yaml
```

**La imagen se pinea a propósito.** `multipass launch` sin imagen usa el alias
por defecto, que cambia cuando sale una LTS nueva; las fixtures del parser se
capturaron contra una versión concreta de `iptables`. Para cambiarla:
`make vm-create VM_IMAGE=24.10`.

Comprobar:

```bash
multipass info firewall-lab
make vm-ip          # anota esta IP: va en el .env y en el frontend
```

## 2. Llevar el repositorio dentro de la VM

```bash
make vm-clone     # primera vez
make vm-sync      # cada vez que quieras llevar cambios
```

El código entra **clonado**, no montado: ver
`docs/adr/0013-el-codigo-entra-en-la-vm-clonado.md`. Se manda con un `git bundle`
transferido por `multipass transfer`, así que **no hacen falta credenciales del
repo privado dentro de la VM**, ni red en la VM, ni permisos especiales sobre la
carpeta del Mac.

> ⚠️ **Solo viaja lo commiteado.** Editar un archivo en el Mac ya no basta:
> commitea y lanza `make vm-sync`. `b0_verify.sh` compara el `HEAD` de los dos
> lados y avisa si el árbol del Mac está sucio, precisamente para que no depures
> código que no es el que corre.

### La alternativa: montar

```bash
make vm-mount
```

Solo funciona si `multipassd` puede leer la carpeta del repo. **En macOS,
`~/Downloads`, `~/Documents` y `~/Desktop` están protegidas por TCC**: el mount
devuelve 0 y el directorio sale vacío dentro de la VM. Para usarlo, ten el repo
fuera de esas carpetas o concede Acceso total al disco a `multipassd`.

> Si el `mount` falla en Apple Silicon, activa además el soporte:
> `multipass set local.privileged-mounts=true`

---

## 3. Paso A2 — Expedición de reconocimiento (solo lectura)

Antes de escribir el parser hay que ver cómo habla iptables **de verdad**. El
formato tiene bastantes casos raros (contadores con sufijo `K`/`M`, orden variable
de los módulos de match, comentarios con espacios) y escribir el parser de memoria
es la vía rápida a un fake que miente.

```bash
make recon
```

Ejecuta cuatro comandos, **ninguno modifica nada**:

```bash
iptables -S                  # formato de reglas
iptables -L -v -n            # formato tabular con contadores
iptables -S FWDASH_INPUT     # el error cuando la cadena no existe
iptables --version
```

Las salidas quedan en `backend/tests/fixtures/iptables_output/`.

**Antes de commitearlas, anonimiza las IPs reales de tu red.** Son las fixtures de
los tests más valiosos del repositorio, pero también un mapa de tu LAN.

Hecho esto, puedes apagar la VM (`multipass stop firewall-lab`) y no volver a
tocarla hasta el bloque B.

---

## 4. Bloque B — Preparar la VM para ejecutar el backend

### 4.1 Dependencias

Lo hace el script de arranque, que además crea el usuario de servicio `fwdash`
y el directorio de datos:

```bash
multipass shell firewall-lab
sudo bash /home/ubuntu/app/infra/scripts/bootstrap_vm.sh
```

> `bootstrap_vm.sh` **no** instala los privilegios de iptables a propósito: eso
> es el §4.2, y se aplica a mano después de leer el ADR-0003.

Dentro de la VM sí se usa `python3 -m venv`: el `uv` del ADR-0005 es una
decisión del **Mac**, donde `ensurepip` está roto. En Ubuntu el venv funciona.

### 4.2 Usuario de servicio y privilegios

Elige **una** de las dos opciones. El razonamiento completo está en
`docs/adr/0003-privilegios-sudo-vs-capabilities.md`.

**Opción A — sudoers** (rápida para desarrollo):

```bash
sudo useradd -r -s /usr/sbin/nologin fwdash
sudo cp infra/sudoers.d/firewall-dashboard /etc/sudoers.d/firewall-dashboard
sudo chmod 0440 /etc/sudoers.d/firewall-dashboard
sudo visudo -c -f /etc/sudoers.d/firewall-dashboard   # validar SIEMPRE antes de confiar
```

> Una línea mal escrita en `/etc/sudoers.d/` puede dejarte sin `sudo`. `visudo -c`
> no es opcional. Y ten una segunda terminal abierta con sesión de root mientras
> lo tocas.

**Opción B — capabilities** (recomendada):

```bash
sudo useradd -r -s /usr/sbin/nologin fwdash
sudo mkdir -p /var/lib/firewall-dashboard && sudo chown fwdash /var/lib/firewall-dashboard
sudo cp infra/systemd/firewall-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now firewall-dashboard
```

### 4.3 Configuración

```bash
cd /home/ubuntu/app/backend
cp .env.example .env
```

Y edita:

```ini
APP_ENV=vm
FIREWALL_BACKEND=iptables            # ← el bloque C, en una línea
API_HOST=192.168.64.X                # la IP de `make vm-ip`
DATABASE_URL=sqlite:////var/lib/firewall-dashboard/firewall.db
JWT_SECRET_KEY=<openssl rand -hex 32>
LOG_FORMAT=json
MANAGEMENT_ALLOWED_CIDR=192.168.64.0/24
```

### 4.4 Migraciones y arranque

```bash
alembic upgrade head
uvicorn app.main:app --host 192.168.64.X --port 8000
```

Desde el Mac:

```bash
curl http://192.168.64.X:8000/health
```

---

## 5. Conectar el frontend

En `frontend/.env`:

```ini
VITE_API_BASE_URL=http://192.168.64.X:8000/api/v1
```

Y en el `.env` del backend, `CORS_ORIGINS=http://localhost:5173`.

---

## Comandos útiles

```bash
multipass list                     # VMs y sus IPs
multipass stop firewall-lab
multipass start firewall-lab
multipass shell firewall-lab       # vía de escape: NO pasa por TCP
multipass delete firewall-lab && multipass purge
```

## Si algo va mal

`docs/RUNBOOK.md`. Léelo antes de aplicar tu primera regla, no después.
