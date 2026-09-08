# Preparar la VM `firewall-lab`

> **Cuándo necesitas esto.** En el bloque A no hace falta: el backend corre en el
> host con `FIREWALL_BACKEND=fake`. Solo necesitas la VM en dos momentos: el paso
> **A2** (captura de fixtures, 20 minutos, solo lectura) y el **bloque B** completo.

---

## Requisitos

Multipass es la misma herramienta en Linux, macOS y Windows; solo cambia cómo se instala.

**macOS (arquitectura ARM):**

```bash
brew install --cask multipass
multipass version
```

**Windows:** ver [la sección de Windows en el README](../README.md#windows). Multipass
se instala en Windows, no dentro de WSL2, porque necesita Hyper-V.

```powershell
winget install Canonical.Multipass
multipass version
```

**Linux:**

```bash
sudo snap install multipass
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
carpeta del host.

> ⚠️ **Solo viaja lo commiteado.** Editar un archivo en el host ya no basta:
> commitea y lanza `make vm-sync`. `b0_verify.sh` compara el `HEAD` de los dos
> lados y avisa si el árbol del host está sucio, precisamente para que no depures
> código que no es el que corre.

### La alternativa: montar

```bash
make vm-mount
```

Solo funciona si `multipassd` puede leer la carpeta del repo. **En el host,
`~/Downloads`, `~/Documents` y `~/Desktop` pueden estar protegidas por TCC**: el mount
devuelve 0 y el directorio sale vacío dentro de la VM. Para usarlo, ten el repo
fuera de esas carpetas o concede Acceso total al disco a `multipassd`.

> Si el `mount` falla en arquitectura ARM, activa además el soporte:
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

Tres pasos: desplegar, dar privilegios y comprobar que los privilegios son los
que crees. El segundo lo aplicas **a mano y revisado**; ninguna herramienta de
este repo toca `/etc/sudoers.d/` ni `/etc/systemd/system/` por su cuenta.

### 4.1 Desplegar

```bash
make vm-sync          # desde el host: lleva a la VM lo COMMITEADO
make vm-deploy        # dentro de la VM: despliega, instala y migra
```

`make vm-deploy` lanza `infra/scripts/deploy_vm.sh`, que es idempotente y hace:

| Qué | Dónde | Detalle |
|---|---|---|
| Usuario de servicio | `fwdash` | de sistema, sin login, sin home, con la cuenta bloqueada |
| Código | `/opt/firewall-dashboard` | copia de `git archive HEAD`, root:root, solo lectura para el servicio ([ADR-0014](adr/0014-el-despliegue-vive-en-opt.md)) |
| Entorno virtual | `/opt/firewall-dashboard/backend/.venv` | de root; el servicio lo ejecuta, no lo escribe |
| Configuración | `/etc/firewall-dashboard/backend.env` | `0640 root:fwdash`, con `JWT_SECRET_KEY` generada. **Fuera del repo** |
| Datos | `/var/lib/firewall-dashboard` | de `fwdash`, `0750` |
| DB | `firewall.db` | `alembic upgrade head` y administrador inicial, ejecutados **como `fwdash`** |

> **El clon sigue en `/home/ubuntu/app`** y es tu área de trabajo. Lo que ejecuta
> el servicio es la copia de `/opt`, y solo llega ahí lo que esté en un commit.
> `/opt/firewall-dashboard/.desplegado` dice qué commit es.

> **Anota la contraseña del admin.** Se genera al crear el `.env` y se imprime
> **una sola vez**. Si la pierdes: borra `/etc/firewall-dashboard/backend.env`,
> vuelve a lanzar el despliegue y se genera otra (los tokens en circulación dejan
> de valer, porque también cambia el `JWT_SECRET_KEY`).

Dentro de la VM sí se usa `python3 -m venv`: el `uv` del [ADR-0005](adr/0005-uv-como-gestor-de-paquetes.md)
es una decisión de esta máquina, donde `ensurepip` está roto. En Ubuntu el venv funciona.

### 4.2 Privilegios: elige **una** de las dos

El razonamiento completo está en
[`adr/0003-privilegios-sudo-vs-capabilities.md`](adr/0003-privilegios-sudo-vs-capabilities.md).

> ⚠️ **No se combinan.** La unidad de systemd lleva `NoNewPrivileges=yes`, y
> `sudo` es setuid: bajo el servicio, `sudo` devuelve `EPERM` aunque el archivo
> de sudoers esté instalado y sea válido. Son alternativas, no capas.

**Opción B — capabilities (recomendada, y la que deja el servicio corriendo):**

```bash
sudo cp /opt/firewall-dashboard/infra/systemd/firewall-dashboard.service \
        /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now firewall-dashboard
```

Con esta opción, `/etc/firewall-dashboard/backend.env` lleva `USE_SUDO=false`.

**Opción A — sudoers (solo para lanzar el backend a mano como `fwdash`):**

```bash
sudo cp /opt/firewall-dashboard/infra/sudoers.d/firewall-dashboard \
        /etc/sudoers.d/firewall-dashboard
sudo chmod 0440 /etc/sudoers.d/firewall-dashboard
sudo visudo -c -f /etc/sudoers.d/firewall-dashboard
```

> Una línea mal escrita en `/etc/sudoers.d/` puede dejarte sin `sudo`. `visudo -c`
> no es opcional. Ten una segunda terminal abierta con sesión de root mientras lo
> tocas — y recuerda que `multipass shell` no pasa por TCP: esa puerta sigue
> abierta pase lo que pase.

### 4.3 Comprobar que los privilegios son los que crees

```bash
make vm-b1            # o, dentro de la VM:
                      # sudo bash /opt/firewall-dashboard/infra/scripts/b1_verify.sh
```

No modifica nada. Comprueba **efectos**, no códigos de salida, y cada afirmación
positiva viene con su contraprueba:

- que `fwdash` **no** puede leer la política sin privilegios (si pudiera, todo lo
  demás no probaría nada);
- que con sudoers sí puede, y que un binario **fuera** del `Cmnd_Alias` es rechazado;
- que con `CAP_NET_ADMIN` ambiental sí puede, y que con **solo** el
  `CapabilityBoundingSet` **no** — que es lo que demuestra cuál de los dos trabaja;
- que un `subprocess.run(['iptables','-S'])` lanzado desde Python **hereda** la
  capability, que es exactamente como la usará el runner del paso B2;
- que el servicio corre como `fwdash` y no como root, con `cap_net_admin` en su
  conjunto efectivo (leído de `/proc/<pid>/status`), y que `/health` responde.

Si algo falla, el journal:

```bash
make vm-service-log
```

### 4.4 Iterar

Cada cambio de código llega a la VM así:

```bash
git commit ...        # solo viaja lo commiteado (ADR-0013)
make vm-sync
make vm-deploy
sudo systemctl restart firewall-dashboard    # dentro de la VM
```

Desde el host:

```bash
curl http://$(make -s vm-ip):8000/health
```

> **`FIREWALL_BACKEND=fake` de momento.** B1 demuestra los *privilegios*, no la
> escritura de reglas: `IptablesBackend` se implementa en B3. Poner `iptables` hoy
> haría que `build_firewall_backend()` lanzara `NotImplementedError` y la
> aplicación arrancaría sin firewall. El interruptor se gira en B3.

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
