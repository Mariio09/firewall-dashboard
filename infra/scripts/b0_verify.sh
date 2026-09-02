#!/usr/bin/env bash
# =========================================================================== #
# b0_verify.sh — paso B0: reprovisionar firewall-lab y demostrar que funciona
#
#   Desde la raiz del repo, EN EL MAC (multipass no existe en el puente):
#     bash infra/scripts/b0_verify.sh 2>&1 | tee b0-verify.log
#
# QUE HACE, EN ORDEN
#   0. Comprobaciones previas y fotografia de la VM actual (release e iptables)
#      ANTES de tocar nada, para poder relanzarla con la MISMA imagen.
#   1. Destruye la VM y la vuelve a crear desde infra/cloud-init.yaml.
#   2. Comprueba que el cloud-init hizo de verdad las tres cosas que dice
#      (packages, write_files, runcmd), no solo que termino sin error.
#   3. Monta el repo y comprueba que el montaje es VIVO en los dos sentidos.
#   4. Resumen con PASS/FALLO y codigo de salida distinto de cero si algo falla.
#
# POR QUE COMPRUEBA LO QUE HACE
# Leccion de A5 y A6: un arnes que no puede demostrar que hizo lo que dice,
# miente en verde. Aqui eso significa no fiarse de `cloud-init status: done`
# (sale done aunque un runcmd falle en silencio) y no fiarse de que el
# `multipass mount` devuelva 0 (devuelve 0 y deja el directorio vacio si el
# soporte de mounts privilegiados esta apagado). Se comprueba el EFECTO.
#
# QUE ES DESTRUCTIVO
# El paso 1 hace `multipass delete --purge`: la VM y su disco se pierden. Las
# fixtures de A2 ya estan commiteadas en el repo, asi que no se pierde nada del
# proyecto, pero el script PIDE CONFIRMACION antes. Con `--si` no la pide.
#
# En la VM solo se LEE iptables (`iptables -S`) para probar que la politica
# nace virgen. No se escribe ni una regla. Nada toca el iptables del Mac.
# =========================================================================== #
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM="${VM:-firewall-lab}"
DESTINO="/home/ubuntu/app"
CLOUD_INIT="$RAIZ/infra/cloud-init.yaml"
FIXTURE_VERSION="$RAIZ/backend/tests/fixtures/iptables_output/version.txt"
IMAGEN_POR_DEFECTO="${VM_IMAGE:-24.04}"
SIN_PREGUNTAR=0
[[ "${1:-}" == "--si" ]] && SIN_PREGUNTAR=1

declare -a RESULTADOS=()
FALLOS=0

paso()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()    { printf '   \033[32mOK\033[0m    %s\n' "$*"; RESULTADOS+=("OK    $*"); }
fallo() { printf '   \033[31mFALLO\033[0m %s\n' "$*"; RESULTADOS+=("FALLO $*"); FALLOS=$((FALLOS+1)); }
aviso() { printf '   \033[33mAVISO\033[0m %s\n' "$*"; RESULTADOS+=("AVISO $*"); }
info()  { printf '         %s\n' "$*"; }

# Ejecuta un comando dentro de la VM y devuelve su salida limpia.
envm() { multipass exec "$VM" -- "$@" 2>/dev/null; }

# --------------------------------------------------------------------------- #
paso "0. Comprobaciones previas"

command -v multipass >/dev/null 2>&1 \
  || { echo "ERROR: no encuentro 'multipass'. Esto se ejecuta en el Mac, no en el puente."; exit 1; }
[[ -f "$CLOUD_INIT" ]] \
  || { echo "ERROR: no encuentro $CLOUD_INIT"; exit 1; }

ok "multipass $(multipass version | head -1 | awk '{print $2}')"
ok "cloud-init.yaml presente"

# --- Fotografia de la VM actual, ANTES de destruirla ------------------------ #
# Sin esto, el relanzamiento usaria el alias por defecto de multipass, que
# cambia con el tiempo: la VM de B0 podria no ser la misma que la de A2 y las
# fixtures del parser dejarian de corresponder con la maquina.
IMAGEN="$IMAGEN_POR_DEFECTO"
VERSION_PREVIA=""
if multipass info "$VM" >/dev/null 2>&1; then
    RELEASE_PREVIA="$(multipass info "$VM" | awk -F': *' '/^Image:/ {print $2}')"
    info "VM actual: $RELEASE_PREVIA"
    # "Ubuntu 24.04 LTS" -> "24.04"
    NUM="$(printf '%s' "$RELEASE_PREVIA" | grep -oE '[0-9]{2}\.[0-9]{2}' | head -1)"
    if [[ -n "$NUM" ]]; then
        IMAGEN="$NUM"
        ok "imagen a reutilizar: $IMAGEN (la misma que tenia la VM de A2)"
    else
        aviso "no he sabido leer la imagen de la VM actual; uso $IMAGEN"
    fi
    if multipass info "$VM" | grep -q 'State:.*Running'; then
        VERSION_PREVIA="$(envm sudo iptables --version | head -1)"
        [[ -n "$VERSION_PREVIA" ]] && info "iptables actual: $VERSION_PREVIA"
    else
        info "la VM esta parada; no leo su iptables (no hace falta arrancarla para borrarla)"
    fi
    EXISTIA=1
else
    info "no hay VM '$VM'; se creara con la imagen $IMAGEN"
    EXISTIA=0
fi

# --------------------------------------------------------------------------- #
paso "1. Recrear la VM desde cloud-init"

if [[ $EXISTIA -eq 1 && $SIN_PREGUNTAR -eq 0 ]]; then
    echo
    echo "   Voy a ejecutar:  multipass delete --purge $VM"
    echo "   Eso BORRA la VM y su disco. Las fixtures de A2 ya estan en el repo."
    read -r -p "   Escribe 'si' para continuar: " RESPUESTA
    [[ "$RESPUESTA" == "si" ]] || { echo "   Cancelado. No se ha tocado nada."; exit 130; }
fi

if [[ $EXISTIA -eq 1 ]]; then
    multipass delete --purge "$VM" \
      && ok "VM anterior destruida" \
      || { fallo "no he podido destruir la VM anterior"; }
fi

info "lanzando (tarda 1-3 min la primera vez, se descarga la imagen)..."
if multipass launch "$IMAGEN" --name "$VM" --cpus 2 --memory 2G --disk 10G \
       --cloud-init "$CLOUD_INIT"; then
    ok "VM creada con la imagen $IMAGEN y el cloud-init del repo"
else
    fallo "multipass launch fallo. Sin VM no hay nada mas que comprobar."
    echo; echo "   Resumen: 1 fallo. Aborto."
    exit 1
fi

# --------------------------------------------------------------------------- #
paso "2. Comprobar que el cloud-init hizo lo que dice"

ESTADO_CI="$(envm cloud-init status --wait | tail -1)"
if [[ "$ESTADO_CI" == *"done"* ]]; then
    ok "cloud-init status: done"
else
    fallo "cloud-init status: ${ESTADO_CI:-sin respuesta}"
fi

# `done` no significa que los runcmd salieran bien: cloud-init los marca como
# terminados aunque devuelvan error. Por eso se comprueban los EFECTOS.

# --- packages: ------------------------------------------------------------- #
for BIN in jq curl python3 iptables; do
    if envm bash -c "command -v $BIN >/dev/null"; then
        ok "paquete instalado: $BIN"
    else
        fallo "falta el binario '$BIN' (lista 'packages' del cloud-init)"
    fi
done
if envm bash -c "command -v netstat >/dev/null"; then
    ok "paquete instalado: net-tools (netstat)"
else
    fallo "falta netstat (paquete net-tools del cloud-init)"
fi

# --- write_files: el motd es el recordatorio de emergencia de B4 ------------ #
if envm grep -q 'firewall-lab' /etc/motd; then
    ok "write_files aplicado: /etc/motd lleva el aviso de la VM"
else
    fallo "/etc/motd no tiene el aviso: write_files no se aplico"
fi
if envm grep -q 'panic_reset.sh' /etc/motd; then
    ok "el motd menciona el reset de emergencia (se lee al entrar, que es cuando hace falta)"
else
    fallo "el motd no menciona panic_reset.sh"
fi

# --- runcmd: --------------------------------------------------------------- #
if envm test -d /var/lib/firewall-dashboard; then
    ok "runcmd aplicado: /var/lib/firewall-dashboard existe"
else
    fallo "no existe /var/lib/firewall-dashboard: el runcmd no corrio"
fi
if envm grep -q 'provisionada' /var/log/firewall-lab-init.log; then
    ok "runcmd aplicado: marca en /var/log/firewall-lab-init.log"
else
    fallo "sin marca en /var/log/firewall-lab-init.log: el runcmd no corrio"
fi

# --- Python: el backend usa StrEnum, que es 3.11+ -------------------------- #
PY_VM="$(envm python3 --version | awk '{print $2}')"
if envm python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)'; then
    ok "python3 de la VM: $PY_VM (>= 3.11, StrEnum disponible)"
else
    fallo "python3 de la VM: $PY_VM. El backend usa StrEnum y necesita 3.11+"
fi

# --- iptables: la version tiene que seguir siendo la de las fixtures -------- #
VERSION_VM="$(envm sudo iptables --version | head -1)"
VERSION_FIXTURE="$(head -1 "$FIXTURE_VERSION" 2>/dev/null)"
info "en la VM:  ${VERSION_VM:-?}"
info "fixture A2: ${VERSION_FIXTURE:-?}"
if [[ -n "$VERSION_VM" && "$VERSION_VM" == "$VERSION_FIXTURE" ]]; then
    ok "iptables coincide con la fixture de A2"
else
    aviso "la version de iptables NO coincide con la fixture de A2."
    aviso "El parser se escribio contra la salida de '$VERSION_FIXTURE'."
    aviso "Antes de B3, recaptura fixtures ('make recon') y pasa test_parser.py."
fi
if [[ "$VERSION_VM" == *"nf_tables"* ]]; then
    ok "el binario es iptables-nft, como asume el parser"
else
    fallo "el backend de iptables no es nf_tables: ${VERSION_VM:-?}"
fi

# --- La politica nace virgen ----------------------------------------------- #
# Prueba de que la siembra de A2 se fue con la VM. Solo lectura.
POLITICA="$(envm sudo iptables -S)"
LINEAS="$(printf '%s\n' "$POLITICA" | grep -c . )"
if [[ "$LINEAS" == "3" ]]; then
    ok "iptables virgen: solo las 3 politicas por defecto, cero reglas"
else
    fallo "iptables no esta virgen: $LINEAS lineas en 'iptables -S'"
    printf '%s\n' "$POLITICA" | sed 's/^/         /'
fi
if printf '%s\n' "$POLITICA" | grep -q 'FWDASH'; then
    fallo "quedan cadenas FWDASH_* de una vida anterior"
else
    ok "no hay cadenas FWDASH_*: la siembra de A2 se fue con la VM"
fi

# --------------------------------------------------------------------------- #
paso "3. Montar el repo y comprobar que el montaje esta VIVO"

if ! multipass mount "$RAIZ" "$VM:$DESTINO"; then
    aviso "el mount fallo. En Apple Silicon suele ser el soporte privilegiado:"
    aviso "  multipass set local.privileged-mounts=true"
    fallo "multipass mount devolvio error"
else
    ok "multipass mount ejecutado ($RAIZ -> $VM:$DESTINO)"
fi

# `mount` puede devolver 0 y dejar el directorio vacio. Lo que prueba que el
# montaje existe es ver el arbol; lo que prueba que es EL MISMO arbol y no una
# copia vieja es que los checksums coincidan y que la escritura pase de un lado
# al otro en los dos sentidos.
if envm test -f "$DESTINO/Makefile"; then
    ok "el codigo del Mac se ve dentro de la VM ($DESTINO/Makefile)"
else
    fallo "no veo $DESTINO/Makefile dentro de la VM: el montaje no esta"
fi

SUMA_MAC="$(shasum -a 256 "$RAIZ/Makefile" | awk '{print $1}')"
SUMA_VM="$(envm sha256sum "$DESTINO/Makefile" | awk '{print $1}')"
if [[ -n "$SUMA_VM" && "$SUMA_MAC" == "$SUMA_VM" ]]; then
    ok "mismo contenido a los dos lados (sha256 del Makefile coincide)"
else
    fallo "el Makefile difiere entre Mac y VM: no es el mismo arbol"
    info "mac: ${SUMA_MAC:0:16}...  vm: ${SUMA_VM:0:16}..."
fi

TESTIGO="$RAIZ/.b0-testigo-$$"
echo "escrito en el Mac a las $(date +%H:%M:%S)" > "$TESTIGO"
if envm test -f "$DESTINO/$(basename "$TESTIGO")"; then
    ok "escritura Mac -> VM: el archivo aparece dentro sin redesplegar nada"
else
    fallo "escritura Mac -> VM: el archivo nuevo no se ve en la VM"
fi
rm -f "$TESTIGO"

TESTIGO_VM=".b0-testigo-vm-$$"
if envm bash -c "echo desde-la-vm > $DESTINO/$TESTIGO_VM"; then
    if [[ -f "$RAIZ/$TESTIGO_VM" ]]; then
        ok "escritura VM -> Mac: el montaje es de lectura y escritura"
    else
        fallo "escritura VM -> Mac: el archivo no llego al Mac"
    fi
else
    fallo "la VM no ha podido escribir en $DESTINO (montaje de solo lectura?)"
fi
rm -f "$RAIZ/$TESTIGO_VM"

# --------------------------------------------------------------------------- #
paso "4. Datos que hacen falta luego"

IP="$(multipass info "$VM" | awk '/IPv4/ {print $2}' | head -1)"
if [[ -n "$IP" ]]; then
    ok "IP de la VM: $IP"
    info "va en backend/.env (API_HOST) y en frontend/.env (VITE_API_BASE_URL)."
    info "Red host-only de Multipass: no esta expuesta a tu LAN."
else
    fallo "la VM no tiene IPv4 todavia"
fi

info ""
info "La via de escape de B4 es 'multipass shell $VM': no pasa por TCP,"
info "asi que sigue funcionando aunque te bloquees la red con iptables."

# --------------------------------------------------------------------------- #
paso "Resumen"

printf '%s\n' "${RESULTADOS[@]}" | sed 's/^/   /'
echo
if [[ $FALLOS -eq 0 ]]; then
    printf '   \033[32mB0 en verde\033[0m — %d comprobaciones, 0 fallos.\n' "${#RESULTADOS[@]}"
    echo "   Siguiente: B1, privilegios (docs/SETUP_VM.md 4.2). Eso lo aplicas tu a mano."
    exit 0
else
    printf '   \033[31m%d fallo(s)\033[0m de %d comprobaciones.\n' "$FALLOS" "${#RESULTADOS[@]}"
    exit 1
fi
