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

# Limite de segundos para cada comando dentro de la VM. macOS no trae `timeout`
# (es de coreutils de GNU), asi que se vigila a mano: el comando va al fondo y
# un centinela lo mata si se pasa del limite.
#
# Sin esto el arnes se CUELGA en vez de fallar, que es la peor forma de fallar:
# ni verde ni rojo, congelado y sin decir donde. Paso de verdad la primera vez
# que se ejecuto B0, leyendo un archivo por el montaje recien hecho: `test -f`
# pasa (solo mira metadatos) y el `sha256sum` de la linea siguiente se queda
# esperando al sshfs que sirve multipassd.
LIMITE_VM="${LIMITE_VM:-20}"

# Ejecuta un comando dentro de la VM y devuelve su salida limpia.
# Devuelve != 0 si el comando falla O si se pasa de LIMITE_VM segundos.
envm() {
    local tmp pid vigia rc
    # Forma portable: `mktemp -t nombre` vale en BSD (macOS) pero GNU exige X's.
    tmp="$(mktemp "${TMPDIR:-/tmp}/b0exec.XXXXXX")"
    multipass exec "$VM" -- "$@" >"$tmp" 2>/dev/null &
    pid=$!
    # El centinela mira cada decima si el comando sigue vivo, para poder salir en
    # cuanto termine. Con un `sleep $LIMITE_VM` de una pieza no se puede: bash no
    # atiende la senal hasta que el sleep acaba, asi que CADA llamada costaria el
    # limite entero (20s x 15 llamadas = 5 minutos de espera pura).
    (
        i=0
        while [[ $i -lt $((LIMITE_VM * 10)) ]]; do
            kill -0 "$pid" 2>/dev/null || exit 0
            sleep 0.1
            i=$((i + 1))
        done
        kill -KILL "$pid" 2>/dev/null
    ) &
    vigia=$!
    wait "$pid" 2>/dev/null; rc=$?
    wait "$vigia" 2>/dev/null
    cat "$tmp"
    rm -f "$tmp"
    return $rc
}

# --------------------------------------------------------------------------- #
paso "0. Comprobaciones previas"

command -v multipass >/dev/null 2>&1 \
  || { echo "ERROR: no encuentro 'multipass'. Esto se ejecuta en el Mac, no en el puente."; exit 1; }
[[ -f "$CLOUD_INIT" ]] \
  || { echo "ERROR: no encuentro $CLOUD_INIT"; exit 1; }

ok "multipass $(multipass version | head -1 | awk '{print $2}')"
ok "cloud-init.yaml presente"


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
paso "3. Llevar el codigo a la VM y comprobar que es EL MISMO"

# El codigo entra CLONADO, no montado (ADR-0013). `multipass mount` devuelve 0 y
# deja el directorio vacio cuando multipassd no puede leer la carpeta de origen
# —el caso de ~/Downloads, protegida por TCC—, y eso no se arregla desde aqui.
# El bundle no necesita credenciales del repo privado, ni red en la VM, ni
# permisos sobre la carpeta del Mac.

if envm bash -c "command -v git >/dev/null"; then
    ok "git presente en la VM (viene del cloud-init)"
else
    fallo "no hay git en la VM: sin el, el codigo no puede entrar"
fi

RAMA="$(git -C "$RAIZ" --no-optional-locks rev-parse --abbrev-ref HEAD 2>/dev/null)"
HEAD_MAC="$(git -C "$RAIZ" --no-optional-locks rev-parse HEAD 2>/dev/null)"
BUNDLE="${TMPDIR:-/tmp}/fwdash-b0.bundle"

# Lo que NO viaja es tan importante como lo que viaja, y es la diferencia real
# frente al montaje: con un mount, editar el archivo bastaba.
if [[ -n "$(git -C "$RAIZ" --no-optional-locks status --porcelain 2>/dev/null)" ]]; then
    aviso "el arbol del Mac tiene cambios SIN COMMITEAR: no van a llegar a la VM."
    aviso "Con el clonado solo viaja lo commiteado. Commitea y 'make vm-sync'."
fi

if git -C "$RAIZ" --no-optional-locks bundle create "$BUNDLE" --all >/dev/null 2>&1; then
    ok "bundle creado en el Mac (rama $RAMA, HEAD ${HEAD_MAC:0:8})"
else
    fallo "no he podido crear el bundle del repo"
fi

if multipass transfer "$BUNDLE" "$VM:/tmp/fwdash.bundle" >/dev/null 2>&1; then
    ok "bundle transferido a la VM (sin credenciales y sin red)"
else
    fallo "multipass transfer fallo"
fi
rm -f "$BUNDLE"

envm rm -rf "$DESTINO" >/dev/null 2>&1
if envm git clone --branch "$RAMA" /tmp/fwdash.bundle "$DESTINO" >/dev/null 2>&1; then
    ok "repo clonado en $VM:$DESTINO"
else
    fallo "el clonado dentro de la VM fallo"
fi

# Contar y leer, no `test -f`: la primera version de este arnes dio verde sobre
# un montaje roto porque `test -f` pasa aunque no se pueda leer nada.
N_ENTRADAS="$(envm bash -c "ls -1 '$DESTINO' 2>/dev/null | wc -l" | tr -d ' ')"
if [[ "${N_ENTRADAS:-0}" -gt 5 ]]; then
    ok "el arbol esta dentro de la VM ($N_ENTRADAS entradas en $DESTINO)"
else
    fallo "$DESTINO tiene ${N_ENTRADAS:-0} entradas: el codigo no ha llegado"
fi

if [[ -n "$(envm head -1 "$DESTINO/Makefile")" ]]; then
    ok "se puede LEER el codigo dentro de la VM"
else
    fallo "no se puede leer $DESTINO/Makefile"
fi

# La prueba fuerte: mismo commit a los dos lados. Compara el arbol ENTERO, no un
# archivo suelto, y ademas demuestra que dentro hay un repo de git de verdad.
HEAD_VM="$(envm git -C "$DESTINO" rev-parse HEAD)"
if [[ -n "$HEAD_VM" && "$HEAD_VM" == "$HEAD_MAC" ]]; then
    ok "la VM esta en el mismo commit que el Mac (${HEAD_MAC:0:8})"
else
    fallo "commits distintos: mac ${HEAD_MAC:0:8} / vm ${HEAD_VM:0:8}"
fi

if [[ -n "$(envm test -x "$DESTINO/infra/scripts/panic_reset.sh" && echo x)" ]]; then
    ok "panic_reset.sh esta en la VM y es ejecutable (lo necesita B4)"
else
    aviso "panic_reset.sh no es ejecutable dentro de la VM; B4 lo necesita"
fi

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
