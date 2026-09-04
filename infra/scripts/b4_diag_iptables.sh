#!/usr/bin/env bash
# =========================================================================== #
# b4_diag_iptables.sh — por que iptables dice "Incompatible with this kernel"
#
#   Ejecutar DENTRO de la VM:
#     multipass shell firewall-lab
#     sudo bash /opt/firewall-dashboard/infra/scripts/b4_diag_iptables.sh
#
#   O desde el Mac:  make vm-diag-iptables
#
# SOLO LECTURA salvo por `modprobe`, que carga modulos del kernel y no cambia
# ninguna regla. Cada comprobacion IMPRIME el error en vez de tragarselo: este
# script existe precisamente porque un `2>/dev/null` sobre iptables convirtio un
# fallo en un dato vacio, y un dato vacio se lee como "no hay nada", que es lo
# contrario de "no se pudo mirar".
# =========================================================================== #
set -uo pipefail

V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }
seccion() { printf "\n%s\n" "$1"; }
dato()    { printf "  %sDATO%s    %s\n" "$A" "$N" "$1"; }
ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; }
mal()     { printf "  %sFALLO%s   %s\n" "$R" "$N" "$1"; }

[[ $EUID -eq 0 ]] || { echo "ERROR: ejecutalo con sudo." >&2; exit 1; }

echo "================================================================"
echo " Diagnostico de iptables en $(hostname)  ·  $(date -Iseconds)"
echo "================================================================"

seccion "1. Que kernel corre, y si tiene sus modulos"
dato "kernel en marcha: $(uname -r)"
dato "arquitectura: $(uname -m)"
MODDIR="/lib/modules/$(uname -r)"
if [[ -d "$MODDIR" ]]; then
    ok "existe $MODDIR"
    dato "modulos netfilter presentes: $(find "$MODDIR/kernel/net" -name '*table*' 2>/dev/null | wc -l)"
else
    mal "NO existe $MODDIR: el kernel en marcha no tiene sus modulos instalados"
    dato "  suele pasar tras actualizar el kernel sin reiniciar, o al reves:"
    dato "  reiniciar a un kernel nuevo cuyo linux-modules aun no esta puesto"
fi
dato "kernels instalados: $(ls /lib/modules 2>/dev/null | tr '\n' ' ')"
dato "paquetes de modulos: $(dpkg -l 2>/dev/null | awk '/^ii +linux-(modules|image)/{print $2}' | tr '\n' ' ')"

seccion "2. Los modulos que iptables necesita"
for modulo in ip_tables iptable_filter x_tables nf_tables nft_compat; do
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$modulo"; then
        ok "cargado: $modulo"
    else
        SALIDA="$(modprobe "$modulo" 2>&1)"
        if [[ $? -eq 0 ]]; then
            ok "cargado ahora con modprobe: $modulo"
        else
            mal "no se puede cargar $modulo: ${SALIDA:-sin mensaje}"
        fi
    fi
done

seccion "3. Que binario es 'iptables' y que dice cada variante"
dato "which iptables: $(command -v iptables || echo 'no esta en el PATH')"
dato "alternativa activa: $(update-alternatives --query iptables 2>/dev/null | awk '/^Value:/{print $2}')"
for binario in /usr/sbin/iptables /usr/sbin/iptables-nft /usr/sbin/iptables-legacy; do
    [[ -x "$binario" ]] || { dato "$binario: no existe"; continue; }
    SALIDA="$("$binario" -S 2>&1)"
    CODIGO=$?
    if [[ $CODIGO -eq 0 ]]; then
        ok "$binario -S funciona ($(grep -c . <<< "$SALIDA") lineas)"
    else
        mal "$binario -S falla (codigo $CODIGO): $(head -1 <<< "$SALIDA")"
    fi
done

seccion "4. El veredicto, y lo que el arnes deberia haber comprobado"
SALIDA="$(iptables -S 2>&1)"; CODIGO=$?
if [[ $CODIGO -eq 0 && -n "$SALIDA" ]]; then
    ok "iptables responde y devuelve contenido: se puede seguir con B4"
    dato "politica INPUT: $(awk '$1=="-P" && $2=="INPUT"{print $3}' <<< "$SALIDA")"
else
    mal "iptables NO responde (codigo $CODIGO): '$(head -1 <<< "$SALIDA")'"
    echo
    echo "  Sin esto, B4 no puede probar nada: el backend no aplicaria ninguna"
    echo "  regla y el arnes veria 'la sesion sigue viva' -- que es su condicion"
    echo "  de EXITO. Verde sobre un sistema donde no se ejecuto nada."
    echo
    echo "  Siguiente paso segun lo que diga la seccion 1:"
    echo "    · faltan los modulos del kernel en marcha  -> apt install linux-modules-\$(uname -r)"
    echo "      o 'apt full-upgrade' + reiniciar, para que kernel y modulos coincidan;"
    echo "    · los modulos estan pero no cargan          -> mirar 'dmesg | tail -20';"
    echo "    · en ultimo caso, 'make vm-provision' recrea la VM entera (dos minutos)."
    echo
    dato "ultimas lineas de dmesg:"
    dmesg 2>/dev/null | tail -10 | sed 's/^/      /'
fi
