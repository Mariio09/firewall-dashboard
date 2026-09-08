#!/usr/bin/env bash
# =========================================================================== #
# panic_reset.sh — recuperar el acceso tras un auto-bloqueo
#
#   Ejecutar DENTRO de la VM:
#     multipass shell firewall-lab
#     sudo bash /home/ubuntu/app/infra/scripts/panic_reset.sh
#
#   Desde el host:  make panic
#
# Recuerda: `multipass shell` NO pasa por TCP. Sigue funcionando aunque hayas
# cerrado la red por completo. Esa es tu via de escape.
#
# Este script es QUIRURGICO: elimina unicamente lo que ha creado la aplicacion.
# No toca reglas de Docker, ufw ni ninguna otra cosa que hubiera en el sistema.
# Esa es precisamente la ventaja de haber usado cadenas propias (ADR-0002).
# =========================================================================== #
set -euo pipefail

PREFIX="${MANAGED_CHAIN_PREFIX:-FWDASH}"
IPTABLES="${IPTABLES_BIN:-/usr/sbin/iptables}"
CHAINS=("INPUT" "OUTPUT" "FORWARD")

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: hay que ejecutarlo como root (usa sudo)." >&2
    exit 1
fi

echo "=== panic_reset — restaurando el acceso ==="
echo

# 1. Copia de seguridad ANTES de tocar nada.
BACKUP="/root/iptables-panic-$(date +%Y%m%d-%H%M%S).rules"
"${IPTABLES}-save" > "$BACKUP" 2>/dev/null || true
echo "[1/4] Estado actual guardado en: $BACKUP"

# 2. Politicas por defecto en ACCEPT. Lo primero, para recuperar conectividad ya.
echo "[2/4] Politicas por defecto -> ACCEPT"
for chain in "${CHAINS[@]}"; do
    "$IPTABLES" -P "$chain" ACCEPT 2>/dev/null || true
done

# 3. Quitar los saltos hacia nuestras cadenas.
echo "[3/4] Eliminando los saltos a ${PREFIX}_*"
for chain in "${CHAINS[@]}"; do
    managed="${PREFIX}_${chain}"
    while "$IPTABLES" -C "$chain" -j "$managed" 2>/dev/null; do
        "$IPTABLES" -D "$chain" -j "$managed"
        echo "      - eliminado salto $chain -> $managed"
    done
done

# 4. Vaciar y borrar las cadenas gestionadas.
echo "[4/4] Vaciando y eliminando las cadenas gestionadas"
for chain in "${CHAINS[@]}"; do
    managed="${PREFIX}_${chain}"
    if "$IPTABLES" -L "$managed" -n >/dev/null 2>&1; then
        "$IPTABLES" -F "$managed"
        "$IPTABLES" -X "$managed"
        echo "      - eliminada cadena $managed"
    fi
done

echo
echo "=== Listo. Estado actual: ==="
"$IPTABLES" -S
echo
echo "Las reglas siguen en la base de datos: no se ha perdido nada."
echo "Revisa cual te bloqueo antes de volver a aplicar (GET /firewall/preview)."
