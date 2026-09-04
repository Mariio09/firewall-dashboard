#!/usr/bin/env bash
# =========================================================================== #
# b5_verify.sh — arnes del paso B5: la suite de contrato contra iptables REAL
#
#   Ejecutar EN EL MAC, desde la raiz del repo:
#     bash infra/scripts/b5_verify.sh | tee b5.log
#
#   O bien:  make b5-verify
#
# ESTE ARNES MODIFICA REGLAS REALES en la VM: la suite crea las cadenas
# FWTEST_*, las cuelga de INPUT/OUTPUT/FORWARD y las borra al terminar. Pide
# confirmacion antes.
#
# --------------------------------------------------------------------------- #
# LO QUE MIDE, Y POR QUE ASI
#
# B3 dejo probado que `IptablesBackend` construye el argv correcto contra un
# iptables SIMULADO. Lo que faltaba —y es B5— es que iptables de VERDAD acepte
# ese argv y devuelva algo que el parser sepa leer. De ahi las dos mitades:
#
#   pytest                       la suite del Mac, otra vez pero DENTRO de la VM
#   pytest -m requires_iptables  contrato contra iptables real + paridad + saltos
#
# Y tres comprobaciones que no son tests de Python sino del arnes, todas salidas
# de las cinco trampas de este proyecto (nota `Estrategia de tests`):
#
#   1. Que el codigo de la VM sea EL MISMO commit que el del Mac. Si no, la
#      suite verde estaria probando otra cosa, y no habria forma de notarlo.
#   2. Que iptables responda ANTES de empezar, y sin silenciar el error: en B4
#      un `2>/dev/null` convirtio un fallo en tres politicas vacias y el arnes se
#      puso verde sobre un sistema donde no se ejecuto nada.
#   3. Que al terminar, la tabla `filter` este EXACTAMENTE como al empezar. Es la
#      unica prueba de que la suite se ha limpiado lo suyo y no ha tocado nada mas
#      -- y en particular, ninguna cadena FWDASH_* del despliegue.
# =========================================================================== #
set -uo pipefail

VM="${VM:-firewall-lab}"
CLON="${CLON:-/home/ubuntu/app}"     # el clon de trabajo: es el que tiene el venv con pytest

V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }
ACIERTOS=0; FALLOS=0
seccion() { printf "\n%s\n" "$1"; }
dato()    { printf "  %sDATO%s    %s\n" "$A" "$N" "$1"; }
ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; ACIERTOS=$((ACIERTOS+1)); }
fallo()   { printf "  %sFALLO%s   %s\n" "$R" "$N" "$1"; FALLOS=$((FALLOS+1)); }

en_vm() { multipass exec "$VM" -- "$@" </dev/null; }

echo "================================================================"
echo " B5 — contrato contra iptables real"
echo " $(date -Iseconds)  ·  $(hostname)  ·  VM=$VM  ·  clon=$CLON"
echo "================================================================"

# --------------------------------------------------------------------------- #
seccion "0. Pre-vuelo (nada se modifica todavia)"

command -v multipass >/dev/null || { echo "ERROR: esto se ejecuta en el Mac." >&2; exit 1; }
[[ "$(multipass info "$VM" 2>/dev/null | awk '/^State:/{print $2}')" == "Running" ]] \
    || { echo "ERROR: la VM no esta corriendo." >&2; exit 1; }

# 1. iptables responde. Sin esto no hay arnes que valga (leccion de B4).
SALIDA_IPT="$(en_vm sudo iptables -S 2>&1)"
CODIGO_IPT=$?
if [[ $CODIGO_IPT -ne 0 || -z "$SALIDA_IPT" ]]; then
    echo "ERROR: iptables no responde dentro de la VM (codigo $CODIGO_IPT)." >&2
    echo "       $(head -1 <<< "$SALIDA_IPT")" >&2
    echo "       Diagnostico: make vm-diag-iptables" >&2
    exit 1
fi
ok "iptables responde en la VM ($(grep -c . <<< "$SALIDA_IPT") lineas)"

# 2. ufw no puede estar filtrando: sus cadenas comparten INPUT con las nuestras.
UFW_ACTIVO='^[Ss]tatus:[[:space:]]*active'
if ! (grep -qE "$UFW_ACTIVO" <<< "Status: active" && ! grep -qE "$UFW_ACTIVO" <<< "Status: inactive"); then
    fallo "el patron de ufw no distingue activo de inactivo: no sigas"; exit 1
fi
ok "contraprueba: el patron distingue 'Status: active' de 'Status: inactive'"
ESTADO_UFW="$(en_vm sudo ufw status 2>/dev/null | head -1)"
REGLAS_UFW="$(grep -c '^-A ufw' <<< "$SALIDA_IPT")"
if grep -qE "$UFW_ACTIVO" <<< "$ESTADO_UFW" || [[ "${REGLAS_UFW:-0}" -gt 0 ]]; then
    echo "ERROR: ufw esta filtrando ('${ESTADO_UFW}', $REGLAS_UFW reglas ufw-*)." >&2
    echo "       Lo que pase en INPUT no seria atribuible a esta suite." >&2
    exit 1
fi
ok "ufw no esta filtrando: lo que pase en INPUT es atribuible a esta suite"

# 3. No pueden quedar restos de una ejecucion anterior.
RESTOS="$(grep -c 'FWTEST_' <<< "$SALIDA_IPT")"
if [[ "${RESTOS:-0}" -gt 0 ]]; then
    echo "ERROR: hay $RESTOS lineas con cadenas FWTEST_* de una ejecucion anterior." >&2
    echo "       Limpialas antes: multipass exec $VM -- sudo iptables -S | grep FWTEST" >&2
    exit 1
fi
ok "no hay restos de FWTEST_* en el sistema"

# 4. EL CODIGO DE LA VM ES EL DEL MAC. Sin esto, un verde no dice de que codigo.
HEAD_MAC="$(git --no-optional-locks rev-parse HEAD)"
HEAD_VM="$(en_vm git -C "$CLON" rev-parse HEAD 2>/dev/null | tr -d '\r')"
if [[ "$HEAD_MAC" != "$HEAD_VM" ]]; then
    echo "ERROR: la VM tiene otro commit." >&2
    echo "       Mac: ${HEAD_MAC:0:12}   VM: ${HEAD_VM:0:12}" >&2
    echo "       Commitea y luego: make vm-sync" >&2
    exit 1
fi
ok "el clon de la VM esta en el mismo commit que el Mac (${HEAD_MAC:0:12})"

SUCIO="$(git --no-optional-locks status --porcelain | grep -v '\.log$')"
if [[ -n "$SUCIO" ]]; then
    dato "hay cambios sin commitear en el Mac: NO viajan a la VM, no se prueban"
    sed 's/^/            /' <<< "$SUCIO"
fi

# 5. El venv del clon tiene pytest. Si no, el fallo saldria como un error de shell.
if en_vm test -x "$CLON/backend/.venv/bin/pytest"; then
    ok "pytest presente en el venv del clon"
else
    echo "ERROR: no hay pytest en $CLON/backend/.venv." >&2
    echo "       Dentro de la VM: cd $CLON && make install" >&2
    exit 1
fi

# La foto de la que depende la comprobacion 3 del encabezado.
POLITICA_ANTES="$(mktemp)"; printf '%s\n' "$SALIDA_IPT" > "$POLITICA_ANTES"
dato "politica guardada para comparar al final ($(wc -l < "$POLITICA_ANTES" | tr -d ' ') lineas)"

echo
echo "  ${A}La suite va a crear cadenas FWTEST_* REALES en $VM y a colgarlas de${N}"
echo "  ${A}INPUT, OUTPUT y FORWARD. Las reglas que descartan trafico apuntan solo${N}"
echo "  ${A}a TEST-NET (RFC 5737), que no existe: no cortan nada tuyo.${N}"
echo "  Las cadenas FWDASH_* del despliegue no se tocan: otro prefijo."
echo
if [[ "${B5_SIN_PREGUNTAR:-0}" != "1" ]]; then
    printf "  Escribe 'si' para continuar: "
    read -r respuesta
    [[ "$respuesta" == "si" ]] || { echo "  Cancelado. No se ha tocado nada."; exit 0; }
fi

# --------------------------------------------------------------------------- #
seccion "1. La suite del Mac, pero dentro de la VM"
# Corre sin privilegios y sin tocar iptables: si esta falla, lo que sigue no se
# puede interpretar.
if en_vm bash -c "cd $CLON/backend && .venv/bin/python -m pytest -q -p no:cacheprovider"; then
    ok "la suite sin iptables pasa dentro de la VM"
else
    fallo "la suite sin iptables NO pasa en la VM: arregla eso antes de seguir"
fi

# --------------------------------------------------------------------------- #
seccion "2. El contrato contra iptables real"
# `sudo` aqui y no en el servicio: bajo systemd la unidad usa CAP_NET_ADMIN
# (ADR-0003), pero una sesion interactiva no la tiene. Los tests preguntan por su
# euid y no anteponen sudo dos veces.
# PYTHONDONTWRITEBYTECODE y -p no:cacheprovider: sin ellos, root deja __pycache__
# y .pytest_cache suyos en el clon y el siguiente `pytest` del usuario falla.
if en_vm sudo env PYTHONDONTWRITEBYTECODE=1 \
        bash -c "cd $CLON/backend && .venv/bin/python -m pytest -m requires_iptables -v -p no:cacheprovider"; then
    ok "la suite que necesita iptables real pasa"
else
    fallo "la suite contra iptables real NO pasa"
fi

# --------------------------------------------------------------------------- #
seccion "3. La VM quedo como estaba"

POLITICA_DESPUES="$(mktemp)"
en_vm sudo iptables -S > "$POLITICA_DESPUES" 2>&1
if [[ ! -s "$POLITICA_DESPUES" ]]; then
    fallo "no se pudo leer la politica final: la seccion queda SIN MEDIR"
elif diff -u "$POLITICA_ANTES" "$POLITICA_DESPUES" > /tmp/b5-diff.txt; then
    ok "la tabla filter esta identica a como estaba antes de la suite"
else
    fallo "la suite dejo restos o algo mas escribio en iptables:"
    sed 's/^/            /' /tmp/b5-diff.txt
fi

RESTOS_FINALES="$(grep -c 'FWTEST_' "$POLITICA_DESPUES")"
if [[ "${RESTOS_FINALES:-0}" -eq 0 ]]; then
    ok "no queda ninguna cadena FWTEST_* en el sistema"
else
    fallo "quedan $RESTOS_FINALES lineas de FWTEST_*: el teardown no se completo"
fi

if grep -q 'FWDASH_' "$POLITICA_ANTES" && ! diff -q \
        <(grep 'FWDASH_' "$POLITICA_ANTES") <(grep 'FWDASH_' "$POLITICA_DESPUES") >/dev/null; then
    fallo "las cadenas FWDASH_* del despliegue CAMBIARON durante la suite"
else
    ok "las cadenas del despliegue (FWDASH_*) siguen como estaban"
fi

rm -f "$POLITICA_ANTES" "$POLITICA_DESPUES"

# --------------------------------------------------------------------------- #
seccion "Resumen"
printf "  %d OK · %d FALLOS\n\n" "$ACIERTOS" "$FALLOS"
if [[ $FALLOS -eq 0 ]]; then
    echo "  El contrato se cumple con iptables de verdad, y el fake responde igual."
    echo "  Es lo que hace que el bloque C sea un cambio de variable de entorno."
fi
exit $(( FALLOS > 0 ? 1 : 0 ))
