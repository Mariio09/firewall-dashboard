.DEFAULT_GOAL := help
SHELL := /bin/bash

BACKEND  := backend
FRONTEND := frontend
VM       := firewall-lab

# El proyecto usa StrEnum, que existe a partir de 3.11. En macOS el `python3` del
# sistema suele ser 3.9: si es tu caso, instala 3.12 (`brew install python@3.12`)
# y lanza `make install PYTHON=python3.12`.
PYTHON ?= python3

.PHONY: help
help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
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

.PHONY: test
test: ## Tests que no necesitan iptables (los que corren en el Mac)
	cd $(BACKEND) && . .venv/bin/activate && pytest

.PHONY: test-cov
test-cov: ## Tests con informe de cobertura
	cd $(BACKEND) && . .venv/bin/activate && pytest --cov=app --cov-report=term-missing --cov-report=html

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

# --------------------------------------------------------------------------- #
# Bloque A2 / B — la VM
# --------------------------------------------------------------------------- #

.PHONY: vm-create
vm-create: ## Crea la VM firewall-lab
	multipass launch --name $(VM) --cpus 2 --memory 2G --disk 10G --cloud-init infra/cloud-init.yaml

.PHONY: vm-mount
vm-mount: ## Monta este repositorio dentro de la VM
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

.PHONY: recon-reset
recon-reset: ## Deshace en la VM lo que sembro `make recon`
	multipass transfer infra/scripts/recon_seed.sh $(VM):/tmp/recon_seed.sh
	multipass exec $(VM) -- sudo bash /tmp/recon_seed.sh reset

.PHONY: test-vm
test-vm: ## Tests que necesitan iptables real (ejecutar DENTRO de la VM)
	cd $(BACKEND) && pytest -m requires_iptables

.PHONY: panic
panic: ## Emergencia: elimina las cadenas FWDASH_* y restaura el acceso
	multipass exec $(VM) -- sudo bash /home/ubuntu/app/infra/scripts/panic_reset.sh
