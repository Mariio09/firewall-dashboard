#!/usr/bin/env bash
# =========================================================================== #
# a6_verify.sh — verificacion de A6 (frontend) en el Mac
#
#   Desde la raiz del repo:
#     bash infra/scripts/a6_verify.sh 2>&1 | tee a6-verify.log
#
# QUE HACE, EN ORDEN
#   1. Levanta el backend (fake) si no hay ya uno respondiendo en el puerto.
#   2. Genera `frontend/src/api/schema.d.ts` desde el OpenAPI vivo.
#   3. Comprueba que el archivo generado es el de verdad y no el calco
#      provisional que se escribio para poder pasar `tsc` sin backend.
#   4. typecheck, lint y build del frontend.
#
# POR QUE COMPRUEBA LO QUE HACE
# Leccion de A5: un arnes que no puede demostrar que hizo lo que dice, miente
# en verde. Aqui eso significa dos cosas concretas: contar los arranques del
# backend (si arranco dos veces, algo lo esta reiniciando y la DB o las claves
# pueden no ser las que crees) y verificar la marca del archivo generado (si
# `gen:api` fallo en silencio, el typecheck estaria validando el calco a mano,
# que es justo lo que no queremos).
#
# NO toca iptables, ni la VM, ni el sistema. Solo lee, genera y compila.
# =========================================================================== #
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKEND="$RAIZ/backend"
FRONTEND="$RAIZ/frontend"
PUERTO="${PUERTO:-8000}"
BASE="http://127.0.0.1:$PUERTO"
LOG_BACKEND="$(mktemp -t a6-backend)"
PID_BACKEND=""
ARRANCADO_AQUI=0

declare -a RESULTADOS=()

paso()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()    { printf '   \033[32mOK\033[0m   %s\n' "$*"; RESULTADOS+=("OK   $*"); }
fallo() { printf '   \033[31mFALLO\033[0m %s\n' "$*"; RESULTADOS+=("FALLO $*"); }

limpiar() {
  if [[ -n "$PID_BACKEND" ]] && kill -0 "$PID_BACKEND" 2>/dev/null; then
    kill "$PID_BACKEND" 2>/dev/null
    wait "$PID_BACKEND" 2>/dev/null
    echo
    echo "-> backend detenido (pid $PID_BACKEND)"
  fi
}
trap limpiar EXIT

# --------------------------------------------------------------------------- #
paso "0. Comprobaciones previas"

[[ -x "$BACKEND/.venv/bin/python" ]] \
  || { echo "ERROR: no existe $BACKEND/.venv. Lanza 'make install'."; exit 1; }
[[ -d "$FRONTEND/node_modules" ]] \
  || { echo "ERROR: no existe $FRONTEND/node_modules. Lanza 'make install'."; exit 1; }
[[ -f "$FRONTEND/.env" ]] \
  || echo "AVISO: no hay frontend/.env; Vite usara el valor por defecto del cliente."
ok "venv y node_modules en su sitio"

# --------------------------------------------------------------------------- #
paso "1. Backend"

if curl -sf --max-time 2 "$BASE/health" >/dev/null 2>&1; then
  ok "ya habia un backend respondiendo en $BASE (se reutiliza)"
else
  echo "-> arrancando uvicorn (sin --reload: un reload a mitad reiniciaria el proceso)"
  (
    cd "$BACKEND" || exit 1
    FIREWALL_BACKEND=fake exec .venv/bin/python -m uvicorn app.main:app \
      --host 127.0.0.1 --port "$PUERTO"
  ) >"$LOG_BACKEND" 2>&1 &
  PID_BACKEND=$!
  ARRANCADO_AQUI=1

  for _ in $(seq 1 40); do
    curl -sf --max-time 1 "$BASE/health" >/dev/null 2>&1 && break
    sleep 0.5
  done

  if curl -sf --max-time 2 "$BASE/health" >/dev/null 2>&1; then
    ok "backend levantado en $BASE (pid $PID_BACKEND)"
  else
    fallo "el backend no responde en $BASE"
    echo "--- ultimas lineas del log del backend ---"
    tail -30 "$LOG_BACKEND"
    exit 1
  fi

  ARRANQUES="$(grep -c "aplicacion_iniciada" "$LOG_BACKEND" 2>/dev/null || echo 0)"
  if [[ "$ARRANQUES" == "1" ]]; then
    ok "el backend arranco exactamente una vez"
  else
    fallo "el backend registro $ARRANQUES arranques (se esperaba 1)"
  fi
fi

BACKEND_ACTIVO="$(curl -sf --max-time 2 "$BASE/ready" | tr ',' '\n' | grep firewall_backend || true)"
echo "-> /ready dice: ${BACKEND_ACTIVO:-sin respuesta}"

# --------------------------------------------------------------------------- #
paso "2. Tipos desde el OpenAPI"

ESQUEMA="$FRONTEND/src/api/schema.d.ts"
if (cd "$FRONTEND" && npm run --silent gen:api >/dev/null 2>&1); then
  ok "npm run gen:api termino sin error"
else
  fallo "npm run gen:api fallo"
  (cd "$FRONTEND" && npm run gen:api 2>&1 | tail -20)
fi

if [[ -f "$ESQUEMA" ]] && ! grep -q "PROVISIONAL_SIN_GENERAR" "$ESQUEMA"; then
  ok "schema.d.ts es el generado ($(wc -l <"$ESQUEMA" | tr -d ' ') lineas)"
else
  fallo "schema.d.ts sigue siendo el calco provisional: el typecheck NO vale"
fi

for TIPO in RuleListItem FirewallStatus ChainDrift TokenPair; do
  grep -q "$TIPO" "$ESQUEMA" 2>/dev/null \
    && ok "el OpenAPI trae $TIPO" \
    || fallo "el OpenAPI no trae $TIPO"
done

# --------------------------------------------------------------------------- #
paso "3. Frontend"

(cd "$FRONTEND" && npm run --silent typecheck) \
  && ok "typecheck" \
  || { fallo "typecheck"; (cd "$FRONTEND" && npm run typecheck 2>&1 | tail -30); }

(cd "$FRONTEND" && npm run --silent lint) \
  && ok "lint" \
  || { fallo "lint"; (cd "$FRONTEND" && npm run lint 2>&1 | tail -30); }

(cd "$FRONTEND" && npm run --silent build >/dev/null) \
  && ok "build" \
  || { fallo "build"; (cd "$FRONTEND" && npm run build 2>&1 | tail -30); }

# --------------------------------------------------------------------------- #
paso "Resumen"

for LINEA in "${RESULTADOS[@]}"; do echo "   $LINEA"; done

if printf '%s\n' "${RESULTADOS[@]}" | grep -q '^FALLO'; then
  echo
  echo "Hay fallos. El log completo es lo que hay que mirar."
  exit 1
fi

echo
echo "Todo en verde."
if [[ "$ARRANCADO_AQUI" == "1" ]]; then
  echo "Para el recorrido manual: 'make dev-backend' en una terminal y"
  echo "'make dev-frontend' en otra, y abre http://127.0.0.1:5173"
fi
