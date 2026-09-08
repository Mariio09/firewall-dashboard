#!/usr/bin/env bash
# =========================================================================== #
# deploy_vm.sh — paso B1: despliega el backend en /opt y lo deja listo
#
#   Ejecutar DENTRO de la VM, como root:
#     multipass shell firewall-lab
#     sudo bash /home/ubuntu/app/infra/scripts/deploy_vm.sh
#
# QUE HACE
#   1. Usuario de servicio `fwdash` (de sistema, sin login, sin home).
#   2. Copia a /opt/firewall-dashboard SOLO LO COMMITEADO (`git archive HEAD`),
#      igual que ADR-0013: si no esta en un commit, no llega a la VM ni a /opt.
#   3. venv del sistema en /opt/firewall-dashboard/backend/.venv, propiedad de
#      root: el servicio lo LEE, no lo escribe.
#   4. /etc/firewall-dashboard/backend.env (0640 root:fwdash) con el secreto JWT
#      fuera del arbol del repo. Si ya existe, NO se toca.
#   5. Migraciones y administrador inicial, ejecutados YA COMO fwdash, para que
#      la DB nazca con el propietario correcto.
#
# QUE NO HACE, A PROPOSITO
#   No instala /etc/sudoers.d/ ni la unidad de systemd. Eso lo aplicas tu, a
#   mano y revisado, tras leer el ADR-0003. Ver docs/SETUP_VM.md §4.2.
#
# Es idempotente: se puede volver a lanzar tras cada `make vm-sync`.
# =========================================================================== #
set -euo pipefail

APP_DIR="${APP_DIR:-/home/ubuntu/app}"          # el clon de git (area de trabajo)
DEPLOY_DIR="${DEPLOY_DIR:-/opt/firewall-dashboard}"  # lo que ejecuta el servicio
CONF_DIR="/etc/firewall-dashboard"
CONF_FILE="$CONF_DIR/backend.env"
DATA_DIR="/var/lib/firewall-dashboard"
SERVICE_USER="fwdash"

paso() { echo; echo "=== $* ==="; }
aviso() { echo "    AVISO: $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: hay que ejecutarlo como root (usa sudo)." >&2
    exit 1
fi

if [[ ! -d "$APP_DIR/.git" ]]; then
    echo "ERROR: $APP_DIR no es un clon de git. Lanza 'make vm-clone' desde el host." >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
paso "1/6  Paquetes del sistema"
# libcap2-bin trae `capsh`, que es como b1_verify.sh lee el conjunto efectivo de
# capabilities de un proceso. rsync hace el despliegue incremental.
apt-get update -qq
apt-get install -y -qq python3-venv python3-pip iptables curl rsync libcap2-bin

# --------------------------------------------------------------------------- #
paso "2/6  Usuario de servicio '$SERVICE_USER'"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "    creado"
else
    echo "    ya existia"
fi
# El servicio no debe poder iniciar sesion ni tener contraseña utilizable.
usermod --lock "$SERVICE_USER" 2>/dev/null || true

# --------------------------------------------------------------------------- #
paso "3/6  Despliegue en $DEPLOY_DIR"
# El repo lo posee `ubuntu`; git se niega a operar sobre un arbol de otro dueño
# ("dubious ownership"), asi que el `git archive` se lanza COMO ese dueño en vez
# de silenciar la comprobacion con safe.directory.
REPO_OWNER="$(stat -c %U "$APP_DIR")"
REVISION="$(runuser -u "$REPO_OWNER" -- git -C "$APP_DIR" rev-parse --short HEAD)"
RAMA="$(runuser -u "$REPO_OWNER" -- git -C "$APP_DIR" rev-parse --abbrev-ref HEAD)"
echo "    origen: $APP_DIR  ($RAMA @ $REVISION)"

SUCIO="$(runuser -u "$REPO_OWNER" -- git -C "$APP_DIR" status --porcelain)"
if [[ -n "$SUCIO" ]]; then
    aviso "el clon tiene cambios sin commitear; NO se despliegan (solo viaja HEAD)."
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/fwdash-deploy.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
runuser -u "$REPO_OWNER" -- git -C "$APP_DIR" archive HEAD | tar -x -C "$STAGE"

mkdir -p "$DEPLOY_DIR"
# --delete deja /opt como una copia exacta del commit; el venv se excluye porque
# no viene del repo y reinstalarlo en cada despliegue costaria minutos.
rsync -a --delete --exclude 'backend/.venv/' "$STAGE"/ "$DEPLOY_DIR"/
chown -R root:root "$DEPLOY_DIR"
# El `-prune` sobre el venv no es cosmetico: sin el, el `chmod 0644` de los
# archivos le quitaria el bit de ejecucion a .venv/bin/uvicorn y el arranque
# siguiente fallaria con 203/EXEC.
find "$DEPLOY_DIR" -path "$DEPLOY_DIR/backend/.venv" -prune -o -type d -exec chmod 0755 {} +
find "$DEPLOY_DIR" -path "$DEPLOY_DIR/backend/.venv" -prune -o -type f -exec chmod 0644 {} +
chmod 0755 "$DEPLOY_DIR"/infra/scripts/*.sh
echo "$REVISION" > "$DEPLOY_DIR/.desplegado"
chmod 0644 "$DEPLOY_DIR/.desplegado"

# El mensaje de bienvenida se REINSTALA en cada despliegue desde `infra/motd.txt`,
# que es su unica fuente. Motivo (B4): el motd que escribio cloud-init se queda
# congelado en lo que el repo decia el dia que se creo la VM, y lo que decia era
# "multipass NO pasa por TCP" -- falso, y justo en el texto que se lee con prisa
# cuando te acabas de bloquear. Refrescarlo aqui hace imposible esa deriva.
if [[ -f "$DEPLOY_DIR/infra/motd.txt" ]]; then
    install -o root -g root -m 0644 "$DEPLOY_DIR/infra/motd.txt" /etc/motd
    echo "    /etc/motd actualizado desde infra/motd.txt"
else
    echo "    AVISO: no hay infra/motd.txt; /etc/motd se queda como estaba" >&2
fi
echo "    $(find "$DEPLOY_DIR" -type f | wc -l) archivos desplegados"

# --------------------------------------------------------------------------- #
paso "4/6  Entorno virtual en $DEPLOY_DIR/backend/.venv"
if [[ ! -x "$DEPLOY_DIR/backend/.venv/bin/python" ]]; then
    python3 -m venv "$DEPLOY_DIR/backend/.venv"
fi
# Instalacion editable: el codigo importado es el de /opt, no una copia mas
# dentro de site-packages. Una sola fuente de verdad por despliegue.
"$DEPLOY_DIR/backend/.venv/bin/pip" install -q --upgrade pip
"$DEPLOY_DIR/backend/.venv/bin/pip" install -q -e "$DEPLOY_DIR/backend"
chown -R root:root "$DEPLOY_DIR/backend/.venv"
echo "    $("$DEPLOY_DIR/backend/.venv/bin/python" --version)"

# --------------------------------------------------------------------------- #
paso "5/6  Configuracion en $CONF_FILE"
install -d -o root -g root -m 0755 "$CONF_DIR"

if [[ -f "$CONF_FILE" ]]; then
    echo "    ya existe: no se toca (contiene el secreto JWT en uso)"
else
    # IP de la interfaz de Multipass. El backend NO puede hacer bind a 127.0.0.1
    # si el frontend del host tiene que llegar; la red host-only de Multipass no
    # esta expuesta a la LAN. Su rango se DERIVA aqui abajo y no se escribe: no
    # es fijo entre maquinas ni entre versiones (en este host es 192.168.252.0/24,
    # no el 192.168.64.0/24 que la documentacion daba por hecho).
    VM_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
    VM_CIDR="$(echo "$VM_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')"
    # El CIDR de gestion NO tiene valor por defecto desde el ADR-0016: es lo que
    # entra en la regla guardian que abre el puerto de la API. Si la derivacion
    # falla —sin interfaz global, un `ip` que imprime otra cosa—, escribir un
    # valor a medias seria peor que no desplegar: la app arrancaria con un
    # guardian que apunta a la nada. Se para aqui.
    if [[ ! "$VM_CIDR" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
        echo "ERROR: no se pudo derivar MANAGEMENT_ALLOWED_CIDR de la interfaz." >&2
        echo "       VM_IP='$VM_IP'  VM_CIDR='$VM_CIDR'" >&2
        echo "       Comprueba: ip -4 -o addr show scope global" >&2
        exit 1
    fi
    ADMIN_PASS="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"

    # OJO: systemd lee este archivo como EnvironmentFile y se queda con la linea
    # ENTERA como valor. Nada de comentarios al final de una linea con valor.
    cat > "$CONF_FILE" <<EOF
# Generado por deploy_vm.sh. Contiene secretos: NO se versiona.
# systemd lo lee como EnvironmentFile: sin comentarios en linea.
APP_ENV=vm
APP_NAME=firewall-dashboard
# INFO no es cosmetico: 'firewall.command.start' se emite a INFO y es la UNICA
# pista de auditoria de que comando se ejecuto contra iptables. Bajar esto a
# WARNING apaga el registro entero. Decidido en B3.
LOG_LEVEL=INFO
LOG_FORMAT=json
API_HOST=$VM_IP
API_PORT=8000
API_V1_PREFIX=/api/v1
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
DATABASE_URL=sqlite:///$DATA_DIR/firewall.db
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASS
# 'iptables' YA FUNCIONA desde B3, y aqui sigue en 'fake' a proposito: en cuanto
# se cambie, el servicio escribira reglas reales por su cuenta al aplicar. Antes
# de dar ese paso tiene que existir la red de seguridad de B4 (panic_reset.sh y
# el RUNBOOK), o un error de configuracion deja la VM sin acceso y sin forma
# documentada de recuperarlo. Cambiarlo es un acto consciente, no un descuido.
FIREWALL_BACKEND=fake
IPTABLES_BIN=/usr/sbin/iptables
IPTABLES_TABLE=filter
MANAGED_CHAIN_PREFIX=FWDASH
# false a proposito: la unidad systemd lleva NoNewPrivileges=yes y sudo es
# setuid, asi que bajo el servicio 'sudo' devuelve EPERM. Ver ADR-0003.
USE_SUDO=false
COMMAND_TIMEOUT_SECONDS=10
AUTO_APPLY=true
MANAGEMENT_PORT=8000
MANAGEMENT_ALLOWED_CIDR=$VM_CIDR
MANAGEMENT_SSH_PORT=22
EOF
    echo "    creado con API_HOST=$VM_IP y MANAGEMENT_ALLOWED_CIDR=$VM_CIDR"
    echo
    echo "    >>> CONTRASEÑA DEL ADMIN: $ADMIN_PASS"
    echo "    >>> Anotala ahora: solo se imprime aqui."
    echo
fi
chown root:"$SERVICE_USER" "$CONF_FILE"
chmod 0640 "$CONF_FILE"

# --------------------------------------------------------------------------- #
paso "6/6  Datos, migraciones y administrador inicial"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"

# Se ejecutan COMO fwdash: si se lanzasen como root, el firewall.db nacería de
# root y el servicio no podria escribir en el. Es el clasico "funciona hasta el
# primer POST". `runuser` en vez de `sudo` porque sudo aqui no aporta nada y
# tendria que pelearse con env_reset.
runuser -u "$SERVICE_USER" -- bash -c "
    set -euo pipefail
    set -a; . '$CONF_FILE'; set +a
    cd '$DEPLOY_DIR/backend'
    .venv/bin/alembic upgrade head
    .venv/bin/python -m app.db.seed
"

cat <<EOF

=== Desplegado ($RAMA @ $REVISION) ===

Pendiente, y a mano a proposito (ADR-0003, docs/SETUP_VM.md §4.2):

  Opcion B — capabilities (recomendada, la que deja el servicio corriendo):
    sudo cp $DEPLOY_DIR/infra/systemd/firewall-dashboard.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now firewall-dashboard

  Opcion A — sudoers (solo para lanzar el backend a mano; NO con la unidad):
    sudo cp $DEPLOY_DIR/infra/sudoers.d/firewall-dashboard /etc/sudoers.d/firewall-dashboard
    sudo chmod 0440 /etc/sudoers.d/firewall-dashboard
    sudo visudo -c -f /etc/sudoers.d/firewall-dashboard

  Y despues, el arnes que comprueba que todo eso hizo lo que dice:
    sudo bash $DEPLOY_DIR/infra/scripts/b1_verify.sh
EOF
