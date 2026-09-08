#!/usr/bin/env bash
# =========================================================================== #
# b4_probe_anchor.sh — B4, paso 0: ¿es real el ancla de recuperacion?
#
#   Ejecutar EN EL HOST, desde la raiz del repo:
#     bash infra/scripts/b4_probe_anchor.sh | tee b4-probe.log
#
#   O bien:  make b4-probe
#
# SOLO LECTURA. Ni una sola regla se crea, se borra ni se modifica, ni en el host
# ni en la VM. Este script solo mide.
#
# --------------------------------------------------------------------------- #
# POR QUE EXISTE
#
# `docs/RUNBOOK.md`, la nota `El problema del auto-bloqueo` y el propio plan de B4
# repiten la misma frase: **"multipass shell no pasa por TCP, asi que sigue
# funcionando aunque cierres la red"**. Esa frase es el ancla de todo el bloque B:
# es la razon por la que romper el firewall a proposito se considera seguro.
#
# Nunca se ha medido. Y es la misma clase de afirmacion que en B1 resulto falsa
# (una unidad de systemd "correcta" que no arrancaba): **algo que no se ha
# ejecutado no esta probado, esta escrito**. Antes de provocar el auto-bloqueo hay
# que saber si la salida de emergencia existe, porque el momento de descubrir que
# no existe no es despues de cerrar la puerta.
#
# `multipass exec` reenvia stdin (leccion de B0): por eso cada llamada lleva
# `</dev/null`, y por eso el probe viaja como archivo con `multipass transfer` en
# vez de por heredoc.
# =========================================================================== #
set -uo pipefail

VM="${VM:-firewall-lab}"
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$RAIZ/infra/scripts/b4_probe_vm.sh"
REMOTO="/tmp/b4_probe_vm.sh"

V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }
seccion() { printf "\n%s\n" "$1"; }
dato()    { printf "  %sDATO%s    %s\n" "$A" "$N" "$1"; }
ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; }
mal()     { printf "  %sOJO%s     %s\n" "$R" "$N" "$1"; }

echo "================================================================"
echo " B4 paso 0 — ¿es real el ancla de recuperacion?"
echo " $(date -Iseconds)  ·  $(hostname)  ·  VM=$VM"
echo "================================================================"

command -v multipass >/dev/null 2>&1 || {
    echo "ERROR: no hay multipass en el PATH. Esto se ejecuta en el host." >&2; exit 1; }
[[ -f "$PROBE" ]] || { echo "ERROR: falta $PROBE" >&2; exit 1; }

# --------------------------------------------------------------------------- #
seccion "M1. El host y la VM"

dato "$(multipass version | tr '\n' ' ')"
ESTADO="$(multipass info "$VM" 2>/dev/null | awk '/^State:/{print $2}')"
dato "estado de $VM: ${ESTADO:-no existe}"
[[ "$ESTADO" == "Running" ]] || {
    echo; echo "ERROR: la VM no esta corriendo. 'multipass start $VM' y repite." >&2; exit 1; }

IP_VM="$(multipass info "$VM" | awk '/IPv4/{print $2}')"
dato "IPv4 de la VM: $IP_VM"

# Snapshots: si existen, hay una via de escape que no depende de la red NI de
# que las reglas se pierdan al reiniciar. Merece la pena saberlo ANTES.
if multipass snapshot --help >/dev/null 2>&1; then
    ok "este multipass soporta 'multipass snapshot' (via de escape independiente de la red)"
    dato "snapshots actuales: $(multipass list --snapshots 2>/dev/null | tail -n +2 | grep -c "^$VM" || echo 0)"
else
    mal "este multipass NO soporta snapshots: una via de escape menos"
fi

# --------------------------------------------------------------------------- #
seccion "M2. Mediciones dentro de la VM"

multipass transfer "$PROBE" "$VM:$REMOTO" || { echo "ERROR: fallo el transfer" >&2; exit 1; }
SALIDA="$(multipass exec "$VM" -- sudo bash "$REMOTO" </dev/null 2>&1)"
echo "$SALIDA"

# --------------------------------------------------------------------------- #
seccion "M3. Veredicto"

if grep -q 'ancla-por-ssh=si' <<< "$SALIDA"; then
    echo
    echo "  ${R}EL ANCLA NO ES LO QUE DICE EL RUNBOOK.${N}"
    echo "  'multipass exec' ha entrado por SSH, es decir, por la red de la VM y"
    echo "  por el puerto 22. Un DROP en INPUT que no deje pasar el 22 desde el"
    echo "  gateway cierra tambien la puerta de emergencia."
    echo
    echo "  Matiz que importa, y que hay que comprobar en el paso siguiente: el"
    echo "  guardian de conntrack (RELATED,ESTABLISHED) mantiene VIVA una sesion"
    echo "  ya abierta. Lo que se pierde es la capacidad de abrir una NUEVA."
    echo "  => tener una 'multipass shell' abierta ANTES de aplicar no es una"
    echo "     recomendacion de estilo: es la diferencia entre poder volver o no."
elif grep -q 'ancla-por-ssh=no' <<< "$SALIDA"; then
    echo
    echo "  ${V}El ancla se sostiene:${N} el proceso no ha entrado por sshd."
    echo "  Aun asi, revisa arriba V3: hace falta ver POR DONDE entro de verdad"
    echo "  (vsock, virtio) antes de darlo por bueno. Que no sea SSH no significa"
    echo "  automaticamente que sobreviva a cerrar la red."
else
    echo "  No se pudo leer el veredicto de la VM. Revisa la salida de M2."
fi

echo
echo "================================================================"
echo " Nada se ha modificado. El siguiente paso (provocar el bloqueo)"
echo " es b4_verify.sh, y no se escribe hasta leer esto."
echo "================================================================"
