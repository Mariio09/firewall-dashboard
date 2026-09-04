#!/usr/bin/env bash
# =========================================================================== #
# b4_verify.sh — arnes del paso B4: el auto-bloqueo, provocado a proposito
#
#   Ejecutar EN EL MAC, desde la raiz del repo:
#     bash infra/scripts/b4_verify.sh <guardian|ssh|cidr|todas> | tee b4.log
#
#   O bien:  make b4-verify FASE=ssh
#
# ESTE ARNES SI MODIFICA REGLAS REALES en la VM. Pide confirmacion antes, y
# **nada se aplica hasta que el rescate automatico esta armado y comprobado**
# dentro de la VM (ver b4_bloqueo.sh).
#
# --------------------------------------------------------------------------- #
# LO QUE MIDE, Y POR QUE ASI
#
# El paso 0 (`make b4-probe`) midio que `multipass exec` entra por SSH:
#     bash <- sudo <- sshd <- sshd <- sshd <- systemd
# y que el otro extremo de la conexion es el gateway, o sea el Mac. La frase que
# el RUNBOOK repetia —"multipass shell no pasa por TCP"— es FALSA en esta
# maquina, y con ella se caia el ancla de todo el bloque B.
#
# De ahi salen las tres fases, y la expectativa de cada una:
#
#   fase      corta          sesion NUEVA (exec)   API (curl al 8000)
#   --------  -------------  --------------------  ------------------
#   guardian  tcp/8000       funciona              FUNCIONA  <- el guardian
#   ssh       tcp/22         FALLA  <- el agujero  funciona
#   cidr      tcp/8000       funciona              FALLA     <- ADR-0016
#
# `guardian` y `cidr` cortan el MISMO puerto con la MISMA regla: lo unico que
# cambia es si el CIDR del guardian es el de verdad. Esa pareja es la prueba de
# que el ADR-0016 no es una precaucion teorica.
#
# Cada medicion se hace DOS VECES, antes y durante el bloqueo. Un `curl` que
# falla no prueba nada si no se ha demostrado antes que funcionaba: podria estar
# fallando porque el servicio no esta levantado.
# =========================================================================== #
set -uo pipefail

FASES="${1:-}"
VM="${VM:-firewall-lab}"
VENTANA="${VENTANA:-90}"     # segundos hasta el rescate automatico
APP=/opt/firewall-dashboard

V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }
ACIERTOS=0; FALLOS=0
seccion() { printf "\n%s\n" "$1"; }
dato()    { printf "  %sDATO%s    %s\n" "$A" "$N" "$1"; }
ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; ACIERTOS=$((ACIERTOS+1)); }
fallo()   { printf "  %sFALLO%s   %s\n" "$R" "$N" "$1"; FALLOS=$((FALLOS+1)); }

# macOS no trae `timeout`. Y hace falta de verdad: en la fase 'ssh' el comando
# que se mide es exactamente el que se queda colgado.
con_limite() {
    local limite="$1"; shift
    local tmp; tmp="$(mktemp)"
    # Sin subshell a proposito: con `( ... ) &` el PID que se guarda es el del
    # subshell, y matarlo dejaria vivo el `multipass exec` colgado por debajo,
    # que es justo el proceso que hay que poder matar en la fase 'ssh'.
    "$@" >"$tmp" 2>&1 & local pid=$!
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1; i=$((i+1))
        if (( i >= limite )); then
            kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
            rm -f "$tmp"; return 124
        fi
    done
    wait "$pid"; local codigo=$?
    rm -f "$tmp"; return $codigo
}

# Igual que con_limite pero imprimiendo lo que capturo, para `$(...)`. Ningun
# `multipass exec` de este arnes puede quedarse colgado sin limite: durante la
# ventana de bloqueo, colgarse es el comportamiento ESPERADO de la mitad de ellos.
salida_limitada() {
    local limite="$1"; shift
    local tmp; tmp="$(mktemp)"
    "$@" >"$tmp" 2>&1 & local pid=$!
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1; i=$((i+1))
        if (( i >= limite )); then kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; break; fi
    done
    wait "$pid" 2>/dev/null
    cat "$tmp"; rm -f "$tmp"
}

sesion_nueva_funciona() { con_limite 15 multipass exec "$VM" -- true; }
api_responde()          { con_limite 10 curl -fsS -o /dev/null "http://$IP_VM:8000/health"; }

[[ "$FASES" =~ ^(guardian|ssh|cidr|todas)$ ]] || {
    echo "uso: bash infra/scripts/b4_verify.sh <guardian|ssh|cidr|todas>" >&2; exit 1; }
[[ "$FASES" == "todas" ]] && FASES="guardian cidr ssh"   # 'ssh' la ultima: es la que corta el rescate

echo "================================================================"
echo " B4 — provocar el auto-bloqueo"
echo " $(date -Iseconds)  ·  $(hostname)  ·  VM=$VM  ·  ventana=${VENTANA}s"
echo "================================================================"

# --------------------------------------------------------------------------- #
seccion "0. Pre-vuelo (nada se modifica todavia)"

command -v multipass >/dev/null || { echo "ERROR: esto se ejecuta en el Mac." >&2; exit 1; }
[[ "$(multipass info "$VM" 2>/dev/null | awk '/^State:/{print $2}')" == "Running" ]] \
    || { echo "ERROR: la VM no esta corriendo." >&2; exit 1; }
IP_VM="$(multipass info "$VM" | awk '/IPv4/{print $2}')"
dato "IP de la VM: $IP_VM"

# LO PRIMERO: que iptables funcione. Sin esto no hay arnes que valga, y el modo
# de fallo es el peor posible -- si `ensure_scaffold` no puede aplicar nada, la
# sesion sigue viva y la API responde, que es justo lo que este arnes considera
# EXITO en la fase 'guardian'. Verde sobre un sistema donde no se ejecuto nada.
# Paso el 2026-09-04: la VM devolvia "iptables: Incompatible with this kernel" y
# el probe, con su `2>/dev/null`, lo enseño como tres politicas vacias.
SALIDA_IPT="$(multipass exec "$VM" -- sudo iptables -S </dev/null 2>&1)"
CODIGO_IPT=$?
if [[ $CODIGO_IPT -ne 0 || -z "$SALIDA_IPT" ]]; then
    echo "ERROR: iptables no responde dentro de la VM (codigo $CODIGO_IPT)." >&2
    echo "       $(head -1 <<< "$SALIDA_IPT")" >&2
    echo "       Diagnostico: make vm-diag-iptables" >&2
    exit 1
fi
ok "iptables responde en la VM ($(grep -c . <<< "$SALIDA_IPT") lineas, politica INPUT=$(awk '$1=="-P" && $2=="INPUT"{print $3}' <<< "$SALIDA_IPT"))"

# ufw es el unico otro dueño posible de estas cadenas. El probe lo encontro
# HABILITADO como servicio; lo que importa no es eso, es si esta ACTIVO.
ESTADO_UFW="$(multipass exec "$VM" -- sudo ufw status </dev/null 2>/dev/null | head -1)"
dato "ufw: ${ESTADO_UFW:-no instalado}"

# `Status: inactive` CONTIENE la palabra 'active'. La primera version de esta
# comprobacion usaba `grep -i active` y daba ufw por encendido con ufw apagado:
# tercera vez en el proyecto que se comprueba la cadena en vez del hecho, y esta
# vez dentro del arnes escrito para no hacerlo. El patron va anclado.
UFW_ACTIVO='^[Ss]tatus:[[:space:]]*active'
# Contraprueba del patron, con las dos salidas que ufw puede dar. Un patron que
# no se ha probado contra el caso que le engaña no es una comprobacion.
if grep -qE "$UFW_ACTIVO" <<< "Status: active" && ! grep -qE "$UFW_ACTIVO" <<< "Status: inactive"; then
    ok "contraprueba: el patron distingue 'Status: active' de 'Status: inactive'"
else
    fallo "el patron de ufw no distingue activo de inactivo: no sigas"
    exit 1
fi

if grep -qE "$UFW_ACTIVO" <<< "$ESTADO_UFW"; then
    echo "ERROR: ufw esta ACTIVO. Sus reglas y las nuestras compartirian INPUT," >&2
    echo "       y ningun resultado de este arnes seria atribuible. Desactivalo" >&2
    echo "       ('sudo ufw disable') o decide antes como conviven." >&2
    exit 1
fi
# Y la comprobacion que no depende de como ufw redacte su estado: si ufw
# estuviera filtrando, habria cadenas `ufw-*` con reglas dentro. Se mira el
# EFECTO en iptables, que es la fuente de verdad para lo que aqui importa.
REGLAS_UFW="$(grep -c '^-A ufw' <<< "$SALIDA_IPT")"   # sobre la salida ya validada arriba
if [[ "${REGLAS_UFW:-0}" -gt 0 ]]; then
    echo "ERROR: hay $REGLAS_UFW reglas en cadenas ufw-* aunque 'ufw status' diga" >&2
    echo "       '${ESTADO_UFW}'. Nadie mas puede estar filtrando durante el arnes." >&2
    exit 1
fi
ok "ufw no esta filtrando: 0 reglas ufw-* en iptables, y su estado es '${ESTADO_UFW}'"
ok "lo que pase en INPUT durante el arnes es atribuible a este arnes"

for archivo in "$APP/infra/scripts/panic_reset.sh" "$APP/infra/scripts/b4_bloqueo.sh"; do
    if multipass exec "$VM" -- test -f "$archivo" </dev/null 2>/dev/null; then
        ok "presente en la VM: $archivo"
    else
        echo "ERROR: falta $archivo en la VM." >&2
        echo "       Commitea, y luego: make vm-sync && make vm-deploy" >&2
        exit 1
    fi
done

# Las dos contrapruebas que dan sentido a todo lo que viene despues.
if sesion_nueva_funciona; then ok "contraprueba: AHORA se puede abrir una sesion nueva"
else fallo "no se puede abrir sesion ni antes de bloquear: para y averigua por que"; exit 1; fi

if api_responde; then
    ok "contraprueba: AHORA la API responde en http://$IP_VM:8000/health"
    API_VIVA=1
else
    dato "la API no responde ahora mismo: las fases 'guardian' y 'cidr' no podran medirla"
    dato "  (levantala con 'make vm-deploy' o 'systemctl start firewall-dashboard')"
    API_VIVA=0
fi

echo
echo "  ${A}Se van a aplicar reglas REALES en $VM, fases: $FASES${N}"
echo "  Cada fase se revierte sola a los ${VENTANA}s (panic_reset + restore del backup)."
echo "  ${A}ANTES DE SEGUIR: abre otra terminal con 'multipass shell $VM'.${N}"
echo "  Esa sesion sobrevive al bloqueo -- la mantiene el guardian de conntrack --"
echo "  y es tu segunda via si algo sale como no esperamos."
echo
if [[ "${B4_SIN_PREGUNTAR:-0}" != "1" ]]; then
    printf "  Escribe 'bloquear' para continuar: "
    read -r respuesta
    [[ "$respuesta" == "bloquear" ]] || { echo "  Cancelado. No se ha tocado nada."; exit 0; }
fi

# --------------------------------------------------------------------------- #
for fase in $FASES; do
    seccion "=== FASE '$fase' ==="

    case "$fase" in
        guardian) ESPERA_SESION=0; ESPERA_API=0 ;;   # 0 = debe seguir funcionando
        ssh)      ESPERA_SESION=1; ESPERA_API=0 ;;   # 1 = debe fallar
        cidr)     ESPERA_SESION=0; ESPERA_API=1 ;;
    esac

    UNIDAD="b4-$fase-$(date +%s)"
    # `--no-block` y con limite. Sin `--no-block`, `systemd-run` espera a que el
    # job de arranque termine y el `multipass exec` no volvia NUNCA: el bloqueo se
    # aplicaba —las cadenas aparecian montadas en la VM— pero el arnes se quedaba
    # clavado en esta linea. Un lanzador que no vuelve no se distingue de un
    # lanzamiento que no ocurrio, asi que ademas de no bloquear, se CONFIRMA por
    # el sello que el propio script escribe en disco. Que el comando vuelva no es
    # la prueba de nada; el sello si.
    con_limite 20 multipass exec "$VM" -- sudo systemd-run --no-block --unit="$UNIDAD" \
        --collect /bin/bash "$APP/infra/scripts/b4_bloqueo.sh" "$fase" "$VENTANA"
    CODIGO_LANZAMIENTO=$?
    T0=$(date +%s)
    if [[ $CODIGO_LANZAMIENTO -eq 124 ]]; then
        dato "el lanzador no volvio en 20s; sigo, y lo confirmo por el sello"
    else
        dato "lanzado $UNIDAD (codigo $CODIGO_LANZAMIENTO)"
    fi

    # Confirmar que el bloqueo esta puesto. El sello lo escribe el propio script en
    # disco, y leerlo exige una sesion SSH nueva... que es EXACTAMENTE lo que la
    # fase 'ssh' corta. Preguntar por el sello ahi daria "nunca dejo su sello" y
    # el arnes se saltaria la unica fase que importa de verdad, dando por no
    # ejecutado el bloqueo que si ocurrio. La confirmacion se aplaza al final,
    # cuando el rescate ya ha devuelto el acceso.
    if [[ "$fase" == "ssh" ]]; then
        dato "fase 'ssh': no se pregunta por el sello ahora (el canal para preguntarlo es"
        dato "  el que se esta cortando). Se comprueba al final, con el log."
        sleep 12
    else
        SELLO=""
        for intento in 1 2 3 4 5 6 7 8 9 10; do
            sleep 3
            SELLO="$(salida_limitada 10 multipass exec "$VM" -- sudo cat "/var/log/b4/$fase.estado")"
            [[ "$SELLO" == "bloqueando" || "$SELLO" == "recuperado" ]] && break
        done
        if [[ -z "$SELLO" ]]; then
            fallo "fase '$fase': el bloqueo nunca dejo su sello. Nada que medir."
            dato "  revisa: multipass exec $VM -- sudo systemctl status $UNIDAD"
            dato "  y:      multipass exec $VM -- sudo cat /var/log/b4/$fase.log"
            continue
        fi
        ok "fase '$fase': el bloqueo esta aplicado (sello='$SELLO')"
    fi

    # --- la medicion, con el bloqueo puesto -------------------------------- #
    if sesion_nueva_funciona; then RESULTADO_SESION=0; else RESULTADO_SESION=1; fi
    if (( API_VIVA )); then
        if api_responde; then RESULTADO_API=0; else RESULTADO_API=1; fi
    else
        RESULTADO_API=-1
    fi

    describir() { [[ "$1" == "0" ]] && echo "funciona" || echo "NO funciona"; }
    dato "sesion nueva: $(describir $RESULTADO_SESION)  ·  esperado: $(describir $ESPERA_SESION)"
    if [[ "$RESULTADO_SESION" == "$ESPERA_SESION" ]]; then
        ok "fase '$fase': la sesion nueva se comporta como se predijo"
    else
        fallo "fase '$fase': la sesion nueva NO se comporta como se predijo"
    fi

    if [[ "$RESULTADO_API" == "-1" ]]; then
        dato "API no medida (no estaba viva antes de empezar)"
    else
        dato "API: $(describir $RESULTADO_API)  ·  esperado: $(describir $ESPERA_API)"
        if [[ "$RESULTADO_API" == "$ESPERA_API" ]]; then
            ok "fase '$fase': la API se comporta como se predijo"
        else
            fallo "fase '$fase': la API NO se comporta como se predijo"
        fi
    fi

    # --- POR QUE se comporto asi: los contadores ---------------------------- #
    # El bloque de contadores que imprime b4_bloqueo.sh sale a los milisegundos de
    # aplicar, cuando todos estan a cero: dice que las reglas existen, no cual de
    # ellas absorbio el trafico. La pregunta "¿por que responde la API?" solo se
    # puede contestar DESPUES de haber hecho el curl, que es aqui.
    CONTADORES="$(salida_limitada 15 multipass exec "$VM" -- \
        sudo iptables -L FWDASH_INPUT -v -n -x --line-numbers)"
    if [[ "$fase" == "ssh" ]]; then
        dato "contadores: no se leen desde aqui (harian falta una sesion nueva, que es"
        dato "  lo que esta cortado). Los toma el propio b4_bloqueo.sh a los 30s."
    elif [[ -z "$CONTADORES" ]]; then
        dato "contadores no legibles"
    else
        printf "%s\n" "$CONTADORES" | sed 's/^/      /'
        PKTS_GUARDIAN="$(awk '/fwdash:guardian:management/{print $2}' <<< "$CONTADORES")"
        PKTS_DROP="$(awk '/b4-auto-bloqueo/{print $2}' <<< "$CONTADORES")"
        dato "paquetes: guardian de gestion=${PKTS_GUARDIAN:-?} · DROP de usuario=${PKTS_DROP:-?}"

        # Aqui esta la prueba del MECANISMO, y es lo que distingue 'guardian' de
        # 'cidr': las dos aplican la MISMA regla al MISMO puerto, y lo unico que
        # cambia es cual de las dos lineas se come los paquetes.
        case "$fase" in
            guardian)
                if [[ "${PKTS_GUARDIAN:-0}" -gt 0 ]]; then
                    ok "fase 'guardian': el guardian de gestion absorbio $PKTS_GUARDIAN paquetes"
                    ok "  => la API no responde 'a pesar' del DROP: responde PORQUE el guardian va antes"
                else
                    fallo "fase 'guardian': el guardian de gestion no conto ni un paquete"
                    fallo "  la API respondio, pero no esta demostrado que sea por el guardian"
                fi ;;
            cidr)
                if [[ "${PKTS_DROP:-0}" -gt 0 ]]; then
                    ok "fase 'cidr': el DROP absorbio $PKTS_DROP paquetes (guardian: ${PKTS_GUARDIAN:-0})"
                    ok "  => con el CIDR equivocado, el guardian deja pasar de largo. ADR-0016, medido"
                else
                    fallo "fase 'cidr': el DROP no conto paquetes: la API cayo por otro motivo"
                fi ;;
        esac
    fi

    # --- esperar al rescate ------------------------------------------------ #
    RESTAN=$(( VENTANA - ($(date +%s) - T0) + 15 ))
    (( RESTAN > 0 )) || RESTAN=5
    dato "esperando ${RESTAN}s al rescate automatico..."
    sleep "$RESTAN"

    # --- ¿se recupero SOLA? ------------------------------------------------ #
    if sesion_nueva_funciona; then
        ok "fase '$fase': la VM se recupero SOLA, sin intervencion manual"
    else
        fallo "fase '$fase': sigue sin poder abrirse una sesion nueva"
        echo "          Entra por la shell que dejaste abierta y ejecuta:" >&2
        echo "            sudo bash $APP/infra/scripts/panic_reset.sh" >&2
        exit 1
    fi

    SELLO="$(salida_limitada 15 multipass exec "$VM" -- sudo cat "/var/log/b4/$fase.estado")"
    if [[ "$SELLO" == "recuperado" ]]; then
        ok "fase '$fase': el rescate dejo su sello en disco ('recuperado')"
    else
        fallo "fase '$fase': el sello dice '${SELLO:-nada}': la recuperacion no fue la programada"
    fi

    FINAL_IPT="$(salida_limitada 15 multipass exec "$VM" -- sudo iptables -S)"
    if [[ -z "$FINAL_IPT" ]]; then
        fallo "fase '$fase': iptables no respondio al terminar la fase"
    fi
    REGLAS="$(grep -c '^-A FWDASH' <<< "$FINAL_IPT")"
    if [[ -n "$FINAL_IPT" && "$REGLAS" == "0" ]]; then
        ok "fase '$fase': no queda ninguna regla FWDASH_* en el sistema"
    else
        fallo "fase '$fase': quedan $REGLAS reglas FWDASH_* sin limpiar"
    fi

    LOG_VM="$(salida_limitada 20 multipass exec "$VM" -- sudo cat "/var/log/b4/$fase.log")"

    # La otra mitad de la fase 'ssh', y la que decide el procedimiento del RUNBOOK:
    # una sesion NUEVA no entra, pero ¿sobrevive la que ya estaba abierta? Lo midio
    # el script desde dentro, mientras el bloqueo estaba puesto.
    if [[ "$fase" == "ssh" ]]; then
        TARDIOS="$(grep -o 'CONTADORES_TARDIOS .*' <<< "$LOG_VM" | head -1)"
        PKTS_DROP="$(sed -n 's/.*drop=\([0-9]*\).*/\1/p' <<< "$TARDIOS")"
        if [[ "${PKTS_DROP:-0}" -gt 0 ]]; then
            ok "fase 'ssh': el DROP del 22 absorbio $PKTS_DROP paquetes ($TARDIOS)"
            ok "  => la sesion nueva no fallo por casualidad: murio en esa regla"
        else
            fallo "fase 'ssh': el DROP no conto paquetes; la sesion nueva fallo por otro motivo"
        fi

        VIVAS="$(awk -F'vivas ahora: ' '/conexiones al 22 vivas ahora/{print $2}' <<< "$LOG_VM" | head -1)"
        if [[ "${VIVAS:-0}" -gt 0 ]]; then
            ok "fase 'ssh': con el 22 cortado seguian VIVAS $VIVAS conexiones ya establecidas"
            ok "  => 'ten una shell abierta antes de aplicar' deja de ser un consejo: es el procedimiento"
        else
            fallo "fase 'ssh': ninguna conexion establecida sobrevivio al bloqueo"
            fallo "  el guardian de conntrack no esta haciendo lo que el RUNBOOK dice que hace"
        fi
    fi

    seccion "Lo que quedo escrito dentro de la VM (fase '$fase')"
    printf "%s\n" "$LOG_VM" | sed 's/^/    /'
done

# --------------------------------------------------------------------------- #
seccion "Resumen"
printf "  %s%d OK%s · %s%d FALLOS%s\n" "$V" "$ACIERTOS" "$N" "$R" "$FALLOS" "$N"
if (( FALLOS == 0 )); then
    echo
    echo "  El auto-bloqueo se provoco, se midio desde fuera y se revirtio solo."
    echo "  Lo que esto deja demostrado, y que antes solo estaba escrito:"
    echo "    · el guardian protege el puerto de gestion, y SOLO ese puerto;"
    echo "    · el 22 -- por donde entra multipass -- no lo protege nadie;"
    echo "    · con el CIDR equivocado, el guardian deja de proteger."
fi
exit $(( FALLOS > 0 ))
