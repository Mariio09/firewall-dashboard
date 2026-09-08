#!/usr/bin/env bash
# =========================================================================== #
# b2_verify.sh — arnes del paso B2: el runner de subprocess
#
#   Ejecutar EN EL HOST, desde la raiz del repo:
#     bash infra/scripts/b2_verify.sh | tee /tmp/b2.log
#
# NO MODIFICA NADA del repo: solo lee, ejecuta la suite y crea binarios de
# mentira en un directorio temporal que borra al salir.
#
# --------------------------------------------------------------------------- #
# LA REGLA DE ESTE ARNES (A5, cobrada cara en B0)
#
# Un arnes que no puede demostrar que hizo lo que dice, MIENTE EN VERDE. Aqui
# nada se da por bueno por codigo de salida: se cuentan tests ejecutados, se
# listan archivos infractores y —lo importante— la prueba de inyeccion se repite
# FUERA de pytest, con su testigo en disco. Un arnes que solo llamase a la misma
# suite que quiere verificar no añadiria informacion ninguna.
#
# Y cada afirmacion positiva con su CONTRAPRUEBA: que el payload no se ejecute no
# prueba nada si no se demuestra que el binario falso SI se ejecuto y recibio ese
# payload como un argumento mas.
# =========================================================================== #
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKEND="$RAIZ/backend"
VENV="$BACKEND/.venv/bin/activate"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ACIERTOS=0; FALLOS=0
V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }

ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; ACIERTOS=$((ACIERTOS+1)); }
fallo()   { printf "  %sFALLO%s   %s\n" "$R" "$N" "$1"; [[ -n "${2:-}" ]] && printf "          %s\n" "$2"; FALLOS=$((FALLOS+1)); }
seccion() { printf "\n%s\n" "$1"; }

echo "================================================================"
echo " B2 — el runner de subprocess"
echo " $(date -Iseconds)  ·  $(hostname)"
echo "================================================================"

if [[ ! -f "$VENV" ]]; then
    echo "ERROR: no existe $VENV. Ejecuta 'make install' primero." >&2
    exit 1
fi
# shellcheck disable=SC1090
cd "$BACKEND" && source "$VENV"

echo " $(python --version)  ·  $(pytest --version 2>&1 | head -1)"

# --------------------------------------------------------------------------- #
seccion "1. La contencion: subprocess vive en un unico archivo"

INFRACTORES="$(grep -rln --include='*.py' '^import subprocess\|^from subprocess' app/ | grep -v '^app/firewall/runner.py$')"
if [[ -z "$INFRACTORES" ]]; then
    ok "solo app/firewall/runner.py importa subprocess"
else
    fallo "otros archivos importan subprocess" "$INFRACTORES"
fi

if grep -rn --include='*.py' 'shell=True' app/ >/dev/null 2>&1; then
    fallo "aparece shell=True en app/"
else
    ok "shell=True no aparece en ningun archivo de app/"
fi

# Contraprueba de las dos anteriores: que el grep encuentra algo cuando lo hay.
if grep -rln --include='*.py' '^import subprocess' app/ | grep -q 'runner.py'; then
    ok "contraprueba: el grep si detecta el import en runner.py"
else
    fallo "el grep no encuentra el import en runner.py: la comprobacion anterior no probaba nada"
fi

# --------------------------------------------------------------------------- #
seccion "2. La suite del runner"

SALIDA_RUNNER="$(pytest tests/unit/firewall/test_runner.py -q 2>&1)"
RESUMEN="$(echo "$SALIDA_RUNNER" | tail -3 | tr -d '\n')"
PASADOS="$(echo "$SALIDA_RUNNER" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)"
PASADOS="${PASADOS:-0}"

if echo "$SALIDA_RUNNER" | grep -qE '[0-9]+ (failed|error)'; then
    fallo "hay tests del runner en rojo" "$RESUMEN"
elif (( PASADOS >= 25 )); then
    ok "$PASADOS tests del runner en verde"
else
    fallo "solo $PASADOS tests ejecutados: se esperaban 25 o mas" "$RESUMEN"
fi

# --------------------------------------------------------------------------- #
seccion "3. La suite entera (que B2 no haya roto el bloque A)"

SALIDA_TODO="$(pytest -q 2>&1)"
TOTAL="$(echo "$SALIDA_TODO" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)"
TOTAL="${TOTAL:-0}"
if echo "$SALIDA_TODO" | grep -qE '[0-9]+ (failed|error)'; then
    fallo "la suite completa tiene rojos" "$(echo "$SALIDA_TODO" | tail -3 | tr -d '\n')"
else
    ok "suite completa en verde: $TOTAL tests"
fi

# --------------------------------------------------------------------------- #
seccion "4. La prueba de inyeccion, FUERA de pytest"

cat > "$TMP/iptables" <<'FALSO'
#!/bin/sh
printf 'ARG:%s\n' "$@" > "TESTIGO_ARGS"
FALSO
sed -i.bak "s|TESTIGO_ARGS|$TMP/args.txt|" "$TMP/iptables" && rm -f "$TMP/iptables.bak"
chmod 755 "$TMP/iptables"

PAYLOAD="; touch $TMP/PWNED; echo"
SALIDA_PY="$(python - "$TMP" "$PAYLOAD" <<'PY' 2>&1
import sys
from pathlib import Path

from app.core.exceptions import SecurityError
from app.firewall.runner import SubprocessRunner

tmp, payload = Path(sys.argv[1]), sys.argv[2]
corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(tmp / "iptables"))

try:
    corredor.run(["rm", "-rf", "/"])
except SecurityError as exc:
    print("ALLOWLIST_OK", exc)
else:
    print("ALLOWLIST_FALLO: no lanzo SecurityError")

resultado = corredor.run(["iptables", "-m", "comment", "--comment", payload])
print("RETORNO", resultado.returncode)
PY
)"

echo "$SALIDA_PY" | sed 's/^/          /'

if [[ -f "$TMP/args.txt" ]]; then
    ok "contraprueba: el binario falso SI se ejecuto (dejo su registro)"
else
    fallo "el binario falso no se ejecuto: nada de lo que sigue prueba nada"
fi

if echo "$SALIDA_PY" | grep -q '^ALLOWLIST_OK'; then
    ok "un binario fuera de la allowlist lanza SecurityError"
else
    fallo "la allowlist no bloqueo el binario"
fi

if grep -qF "ARG:$PAYLOAD" "$TMP/args.txt" 2>/dev/null; then
    ok "el payload llego literal, como un argumento mas"
else
    fallo "el payload no llego intacto" "$(cat "$TMP/args.txt" 2>/dev/null)"
fi

if [[ -e "$TMP/PWNED" ]]; then
    fallo "EL PAYLOAD SE EJECUTO: existe $TMP/PWNED"
else
    ok "el payload no se ejecuto: no hay testigo en disco"
fi

# --------------------------------------------------------------------------- #
seccion "5. Linters y tipos"

for comprobacion in "ruff check ." "ruff format --check ." "mypy app" "bandit -c pyproject.toml -q -r app"; do
    if SALIDA="$($comprobacion 2>&1)"; then
        ok "$comprobacion"
    else
        fallo "$comprobacion" "$(echo "$SALIDA" | tail -5 | tr '\n' ' ')"
    fi
done

# --------------------------------------------------------------------------- #
echo
echo "================================================================"
printf " Resultado: %s%d OK%s, %s%d FALLOS%s\n" "$V" "$ACIERTOS" "$N" "$R" "$FALLOS" "$N"
echo "================================================================"
(( FALLOS == 0 )) || exit 1
