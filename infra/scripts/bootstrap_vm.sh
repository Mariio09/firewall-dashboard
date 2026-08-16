#!/usr/bin/env bash
# =========================================================================== #
# bootstrap_vm.sh — preparar firewall-lab para ejecutar el backend (bloque B)
#
#   Ejecutar DENTRO de la VM:
#     multipass shell firewall-lab
#     sudo bash /home/ubuntu/app/infra/scripts/bootstrap_vm.sh
#
# NO instala los privilegios de iptables: eso lo haces tu a mano tras leer el
# ADR-0003 y decidir entre sudoers y capabilities. Ver docs/SETUP_VM.md §4.2.
# =========================================================================== #
set -euo pipefail

APP_DIR="${APP_DIR:-/home/ubuntu/app}"
DATA_DIR="/var/lib/firewall-dashboard"
SERVICE_USER="fwdash"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: hay que ejecutarlo como root (usa sudo)." >&2
    exit 1
fi

echo "[1/4] Paquetes del sistema"
apt-get update -qq
apt-get install -y -qq python3-venv python3-pip iptables curl

echo "[2/4] Usuario de servicio '$SERVICE_USER'"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
    echo "      creado"
else
    echo "      ya existia"
fi

echo "[3/4] Directorio de datos $DATA_DIR"
mkdir -p "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"

echo "[4/4] Entorno virtual de Python"
if [[ -d "$APP_DIR/backend" ]]; then
    sudo -u ubuntu python3 -m venv "$APP_DIR/backend/.venv"
    sudo -u ubuntu "$APP_DIR/backend/.venv/bin/pip" install -q -e "$APP_DIR/backend[dev]"
    echo "      dependencias instaladas"
else
    echo "      AVISO: no encuentro $APP_DIR/backend."
    echo "      ¿Has montado el repositorio?  make vm-mount"
fi

cat <<'EOF'

=== Listo ===

Pendiente, y a mano a proposito:

  1. Privilegios de iptables. Lee docs/adr/0003-privilegios-sudo-vs-capabilities.md
     y elige:
       A) sudoers      -> docs/SETUP_VM.md §4.2, opcion A
       B) capabilities -> docs/SETUP_VM.md §4.2, opcion B  (recomendada)

  2. Configuracion:
       cp backend/.env.example backend/.env
       # FIREWALL_BACKEND=iptables, API_HOST=<ip de la VM>, JWT_SECRET_KEY=...

  3. Migraciones:
       cd backend && .venv/bin/alembic upgrade head

Antes de aplicar tu primera regla real, lee docs/RUNBOOK.md.
EOF
