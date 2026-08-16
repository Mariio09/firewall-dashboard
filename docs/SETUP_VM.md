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

```bash
make vm-create
```

Equivale a:

```bash
multipass launch --name firewall-lab --cpus 2 --memory 2G --disk 10G \
                 --cloud-init infra/cloud-init.yaml
```

Comprobar:

```bash
multipass info firewall-lab
make vm-ip          # anota esta IP: va en el .env y en el frontend
```

## 2. Montar el repositorio dentro de la VM

```bash
make vm-mount
```

Editas en el Mac con tu editor de siempre y el proceso corre en la VM sobre los
mismos archivos. Sin `rsync`, sin redespliegues, sin dos copias del código
divergiendo.

> Si el `mount` falla en Apple Silicon, activa el soporte:
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

```bash
multipass shell firewall-lab
sudo apt update && sudo apt install -y python3-venv python3-pip iptables
cd /home/ubuntu/app/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

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
