.DEFAULT_GOAL := help
SHELL := /bin/bash

BACKEND  := backend
FRONTEND := frontend
VM       := firewall-lab
# Imagen de la VM. Se PINEA a proposito: `multipass launch` sin imagen usa el
# alias por defecto, que cambia con el tiempo, y las fixtures del parser (A2)
# se capturaron contra una version concreta de iptables.
VM_IMAGE ?= 24.04
# Rama que se lleva a la VM. Por defecto, la que tengas activa.
RAMA     ?= $(shell git --no-optional-locks rev-parse --abbrev-ref HEAD)
BUNDLE   := /tmp/fwdash.bundle

# El proyecto usa StrEnum, que existe a partir de 3.11. En macOS el `python3` del
# sistema suele ser 3.9: si es tu caso, instala 3.12 (`brew install python@3.12`)
# y lanza `make install PYTHON=python3.12`.
PYTHON ?= python3

.PHONY: help
help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------------------- #
# Bloque A — todo en el Mac, sin VM
# --------------------------------------------------------------------------- #

.PHONY: install
install: ## Instala dependencias de backend y frontend
	@if command -v uv >/dev/null 2>&1; then \
		echo "-> uv detectado, usandolo (evita ensurepip)"; \
		cd $(BACKEND) && uv venv --python 3.12 .venv \
			&& uv pip install --python .venv/bin/python -e ".[dev]"; \
	else \
		$(PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
			|| { echo "ERROR: se necesita Python 3.11+ o uv (brew install uv)"; exit 1; }; \
		cd $(BACKEND) && $(PYTHON) -m venv .venv && . .venv/bin/activate \
			&& pip install --upgrade pip && pip install -e ".[dev]"; \
	fi
	cd $(FRONTEND) && npm install

.PHONY: dev-backend
dev-backend: ## Levanta el backend con FIREWALL_BACKEND=fake
	cd $(BACKEND) && . .venv/bin/activate && uvicorn app.main:app --reload --port 8000

.PHONY: dev-frontend
dev-frontend: ## Levanta el servidor de desarrollo de Vite
	cd $(FRONTEND) && npm run dev

.PHONY: gen-api
gen-api: ## Regenera los tipos del frontend desde el OpenAPI (backend en marcha)
	cd $(FRONTEND) && npm run gen:api

.PHONY: front-check
front-check: ## A6: levanta el backend, regenera tipos, typecheck, lint y build
	bash infra/scripts/a6_verify.sh

.PHONY: test
test: ## Tests que no necesitan iptables (los que corren en el Mac)
	cd $(BACKEND) && . .venv/bin/activate && pytest

.PHONY: test-cov
test-cov: ## Tests con informe de cobertura
	cd $(BACKEND) && . .venv/bin/activate && pytest --cov=app --cov-report=term-missing --cov-report=html

.PHONY: b2-verify
b2-verify: ## B2: arnes del runner de subprocess (se ejecuta en el Mac)
	bash infra/scripts/b2_verify.sh

.PHONY: b3-verify
b3-verify: ## B3: arnes de IptablesBackend contra un iptables simulado (en el Mac)
	bash infra/scripts/b3_verify.sh

.PHONY: lint
lint: ## ruff + mypy + bandit
	cd $(BACKEND) && . .venv/bin/activate && ruff check . && ruff format --check . && mypy app && bandit -c pyproject.toml -r app

.PHONY: format
format: ## Formatea y autocorrige
	cd $(BACKEND) && . .venv/bin/activate && ruff format . && ruff check --fix .

.PHONY: audit
audit: ## Auditoria de dependencias vulnerables
	cd $(BACKEND) && . .venv/bin/activate && pip-audit

.PHONY: migrate
migrate: ## Aplica las migraciones pendientes
	cd $(BACKEND) && . .venv/bin/activate && alembic upgrade head

.PHONY: migration
migration: ## Crea una migracion nueva:  make migration m="add rules table"
	cd $(BACKEND) && . .venv/bin/activate && alembic revision --autogenerate -m "$(m)"

.PHONY: seed
seed: ## Crea el administrador inicial (idempotente). Necesita la DB migrada.
	cd $(BACKEND) && . .venv/bin/activate && python -m app.db.seed

# --------------------------------------------------------------------------- #
# Bloque A2 / B — la VM
# --------------------------------------------------------------------------- #

.PHONY: vm-create
vm-create: ## Crea la VM firewall-lab
	multipass launch $(VM_IMAGE) --name $(VM) --cpus 2 --memory 2G --disk 10G \
		--cloud-init infra/cloud-init.yaml

.PHONY: vm-provision
vm-provision: ## B0: recrea la VM, le mete el codigo y lo verifica todo
	bash infra/scripts/b0_verify.sh

.PHONY: vm-smoke
vm-smoke: ## Recorre el arnes de B0 con un multipass falso (no necesita VM)
	bash infra/scripts/b0_smoke.sh

# El codigo entra en la VM CLONADO, no montado: ver ADR-0013. Se manda por un
# `git bundle` transferido, asi que no hacen falta credenciales del repo privado
# dentro de la VM, ni red, ni permisos de TCC sobre la carpeta del Mac.
# Solo viaja lo COMMITEADO.

.PHONY: vm-clone
vm-clone: ## Clona el repo dentro de la VM desde un bundle (primera vez)
	@SUCIO="$$(git --no-optional-locks status --porcelain)"; \
	if [ -n "$$SUCIO" ]; then \
		printf '\033[33mAVISO\033[0m: hay cambios sin commitear. NO viajan a la VM (ADR-0013):\n'; \
		echo "$$SUCIO" | sed 's/^/       /'; \
		printf '       Si esperabas que uno de estos arreglara algo, commitealo antes.\n\n'; \
	fi
	git --no-optional-locks bundle create $(BUNDLE) --all
	multipass transfer $(BUNDLE) $(VM):$(BUNDLE)
	-multipass exec $(VM) -- rm -rf /home/ubuntu/app </dev/null
	multipass exec $(VM) -- git clone --branch $(RAMA) $(BUNDLE) /home/ubuntu/app </dev/null
	@rm -f $(BUNDLE)
	@echo "Clonado en $(VM):/home/ubuntu/app (rama $(RAMA))"

.PHONY: vm-sync
vm-sync: ## Lleva a la VM lo commiteado de la rama actual
	@SUCIO="$$(git --no-optional-locks status --porcelain)"; \
	if [ -n "$$SUCIO" ]; then \
		printf '\033[33mAVISO\033[0m: hay cambios sin commitear. NO viajan a la VM (ADR-0013):\n'; \
		echo "$$SUCIO" | sed 's/^/       /'; \
		printf '       Si esperabas que uno de estos arreglara algo, commitealo antes.\n\n'; \
	fi
	git --no-optional-locks bundle create $(BUNDLE) --all
	multipass transfer $(BUNDLE) $(VM):$(BUNDLE)
	multipass exec $(VM) -- git -C /home/ubuntu/app fetch $(BUNDLE) $(RAMA) </dev/null
	multipass exec $(VM) -- git -C /home/ubuntu/app reset --hard FETCH_HEAD </dev/null
	@rm -f $(BUNDLE)
	@echo "VM sincronizada con $(RAMA). Lo NO commiteado no ha viajado."

# --------------------------------------------------------------------------- #
# Bloque B1 — privilegios
#
# El despliegue y el arnes NO instalan sudoers ni la unidad de systemd: eso se
# aplica a mano y revisado (ADR-0003, docs/SETUP_VM.md §4.2).
# `</dev/null` en cada `multipass exec` no es adorno: exec reenvia stdin, y sin
# redirigirlo el comando remoto se queda esperando entrada que no llega.
# --------------------------------------------------------------------------- #

.PHONY: vm-deploy
vm-deploy: ## B1: despliega en /opt de la VM lo commiteado, con venv, .env y DB
	multipass exec $(VM) -- sudo bash /home/ubuntu/app/infra/scripts/deploy_vm.sh </dev/null

.PHONY: vm-b1
vm-b1: ## B1: arnes de privilegios dentro de la VM (no modifica nada)
	multipass exec $(VM) -- sudo bash /opt/firewall-dashboard/infra/scripts/b1_verify.sh </dev/null

.PHONY: vm-service-log
vm-service-log: ## Ultimas lineas del journal del servicio en la VM
	multipass exec $(VM) -- sudo journalctl -u firewall-dashboard -n 50 --no-pager </dev/null

.PHONY: vm-mount
vm-mount: ## (alternativa) Monta el repo en la VM. Necesita que multipassd pueda leer la carpeta
	multipass mount $(PWD) $(VM):/home/ubuntu/app

.PHONY: vm-shell
vm-shell: ## Abre una shell en la VM (NO pasa por TCP: funciona aunque cierres la red)
	multipass shell $(VM)

.PHONY: vm-ip
vm-ip: ## Muestra la IP de la VM
	@multipass info $(VM) | grep IPv4 | awk '{print $$2}'

FIXTURES := $(BACKEND)/tests/fixtures/iptables_output
IPT      := sudo env LC_ALL=C iptables

.PHONY: recon
recon: recon-limpio recon-seed recon-cargado ## Paso A2: captura fixtures reales de iptables
	@echo
	@echo "Listo: $(FIXTURES)  (ver su README.md)"
	@echo "Para dejar la VM como estaba:  make recon-reset"

.PHONY: recon-limpio
recon-limpio: ## A2 (1/3): captura el estado virgen de la VM. Solo lectura.
	@echo "--- A2 1/3: estado limpio (ningun comando modifica reglas) ---"
	@mkdir -p $(FIXTURES)/limpio
	multipass exec $(VM) -- $(IPT) --version    > $(FIXTURES)/version.txt
	multipass exec $(VM) -- $(IPT) -S           > $(FIXTURES)/limpio/save.txt
	multipass exec $(VM) -- $(IPT) -L -v -n     > $(FIXTURES)/limpio/list_verbose.txt
	@# Como falla cuando la cadena NO existe. Hay que capturarlo ANTES de sembrar,
	@# porque despues la cadena existe y el comando deja de fallar.
	-multipass exec $(VM) -- $(IPT) -S FWDASH_INPUT > $(FIXTURES)/error_chain_missing.txt 2>&1

.PHONY: recon-seed
recon-seed: ## A2 (2/3): carga el ruleset representativo DENTRO de la VM
	@echo "--- A2 2/3: sembrando (solo dentro de la VM; ver cabecera del script) ---"
	multipass transfer infra/scripts/recon_seed.sh $(VM):/tmp/recon_seed.sh
	multipass exec $(VM) -- sudo bash /tmp/recon_seed.sh

.PHONY: recon-cargado
recon-cargado: ## A2 (3/3): captura con el ruleset cargado. Solo lectura.
	@echo "--- A2 3/3: estado cargado (ningun comando modifica reglas) ---"
	@mkdir -p $(FIXTURES)/cargado
	multipass exec $(VM) -- $(IPT) -S           > $(FIXTURES)/cargado/save.txt
	multipass exec $(VM) -- $(IPT) -L -v -n     > $(FIXTURES)/cargado/list_verbose.txt
	multipass exec $(VM) -- $(IPT) -L -v -n -x  > $(FIXTURES)/cargado/list_verbose_exact.txt
	multipass exec $(VM) -- sudo env LC_ALL=C iptables-save > $(FIXTURES)/cargado/iptables_save.txt

# `make recon` sobrescribe las fixtures commiteadas. Cuando lo que quieres es
# SABER si han cambiado —por ejemplo tras recrear la VM con otra version de
# iptables— hay que capturar a otro sitio y comparar, no machacar la evidencia.
# FIXTURES se puede sobreescribir en la linea de comandos, asi que basta con eso.
NUEVAS := /tmp/recon-nuevas

.PHONY: recon-diff
recon-diff: ## Captura fixtures a /tmp y las compara con las commiteadas. NO toca el repo
	@rm -rf $(NUEVAS)
	@$(MAKE) --no-print-directory recon FIXTURES=$(NUEVAS)
	@echo
	@echo "=== diferencias con las fixtures commiteadas ==="
	@if diff -ru $(FIXTURES) $(NUEVAS); then \
		echo "SIN DIFERENCIAS: esta version de iptables imprime igual."; \
		echo "El parser no necesita cambios; basta con actualizar version.txt."; \
	else \
		echo; \
		echo "HAY DIFERENCIAS (arriba). Eso es justo lo que el parser tiene que aguantar."; \
		echo "Siguiente paso: 'make test' y ver si test_parser.py sigue pasando."; \
	fi

.PHONY: recon-reset
recon-reset: ## Deshace en la VM lo que sembro `make recon`
	multipass transfer infra/scripts/recon_seed.sh $(VM):/tmp/recon_seed.sh
	multipass exec $(VM) -- sudo bash /tmp/recon_seed.sh reset

.PHONY: test-vm
test-vm: ## B5: las dos mitades de la suite (ejecutar DENTRO de la VM)
	@# Primero la del Mac: si esta falla, lo que venga despues no se puede interpretar.
	cd $(BACKEND) && .venv/bin/python -m pytest -q -p no:cacheprovider
	@# Y la que necesita privilegios. `sudo` aqui y no en el servicio: la unidad
	@# systemd usa CAP_NET_ADMIN (ADR-0003), pero una sesion interactiva no la tiene.
	@# PYTHONDONTWRITEBYTECODE evita que root deje __pycache__ suyos en el clon.
	cd $(BACKEND) && sudo env PYTHONDONTWRITEBYTECODE=1 \
		.venv/bin/python -m pytest -m requires_iptables -v -p no:cacheprovider

# --------------------------------------------------------------------------- #
# Bloque B4 — el auto-bloqueo
# --------------------------------------------------------------------------- #

.PHONY: b4-probe
b4-probe: ## B4 paso 0: mide si el ancla de recuperacion es real. SOLO LECTURA
	bash infra/scripts/b4_probe_anchor.sh

FASE ?= todas
APP_DIR ?= /opt/firewall-dashboard

.PHONY: vm-diag-iptables
vm-diag-iptables: ## Diagnostica por que iptables no responde dentro de la VM
	multipass exec $(VM) -- sudo bash $(APP_DIR)/infra/scripts/b4_diag_iptables.sh </dev/null

.PHONY: b4-verify
b4-verify: ## B4: provoca el auto-bloqueo en la VM y comprueba que se vuelve. FASE=guardian|ssh|cidr|todas
	bash infra/scripts/b4_verify.sh $(FASE)

# --------------------------------------------------------------------------- #
# Bloque B5 — el contrato contra iptables real
# --------------------------------------------------------------------------- #

.PHONY: b5-verify
b5-verify: ## B5: lanza la suite de contrato contra iptables real DENTRO de la VM
	bash infra/scripts/b5_verify.sh

# --------------------------------------------------------------------------- #
# Bloque C — la interconexion
#
# `c-verify` es el bloque C entero de una pasada: red (C1), el cambio a iptables
# real (C0), la reconciliacion de arranque (C2), el drift provocado a mano (C3) y
# el recorrido completo de la API al kernel (C4). Pide confirmacion, arma la
# reversion ANTES de conmutar y limpia lo que siembra.
#
# Necesita que la VM tenga EL MISMO commit que el Mac y que /opt este desplegado:
#   git commit ... && make vm-sync && make vm-deploy && make c-verify
# --------------------------------------------------------------------------- #

.PHONY: c-verify
c-verify: ## C: arnes del bloque C entero en la VM. FASE=todas|c0|c1|c2|c3|c4
	bash infra/scripts/c_verify.sh $(FASE)

.PHONY: c-front
c-front: ## C1: apunta frontend/.env a la IP actual de la VM (sin tocar nada mas)
	bash infra/scripts/c_verify.sh c1

.PHONY: panic
panic: ## Emergencia: elimina las cadenas FWDASH_* y restaura el acceso
	@# `</dev/null` NO es adorno (leccion de B0): `multipass exec` reenvia stdin y
	@# sin redirigirlo el comando remoto se queda esperando entrada que no llega.
	@# En una emergencia, un comando que se cuelga en silencio es lo peor posible.
	@# Se intenta primero el despliegue de /opt, que es lo que corre de verdad, y
	@# se cae al clon de trabajo si aquel no esta.
	multipass exec $(VM) -- sudo bash -c \
		'if [ -f /opt/firewall-dashboard/infra/scripts/panic_reset.sh ]; then \
		    bash /opt/firewall-dashboard/infra/scripts/panic_reset.sh; \
		 else \
		    bash /home/ubuntu/app/infra/scripts/panic_reset.sh; \
		 fi' </dev/null
