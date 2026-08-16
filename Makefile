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
	@$(PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
		|| { echo "ERROR: se necesita Python 3.11+. Prueba: make install PYTHON=python3.12"; exit 1; }
	cd $(BACKEND) && $(PYTHON) -m venv .venv && . .venv/bin/activate \
		&& pip install --upgrade pip && pip install -e ".[dev]"
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

.PHONY: recon
recon: ## Paso A2: captura salidas reales de iptables como fixtures (SOLO LECTURA)
	@echo "Capturando fixtures desde $(VM)... (ningun comando modifica reglas)"
	@mkdir -p $(BACKEND)/tests/fixtures/iptables_output
	multipass exec $(VM) -- sudo iptables -S            > $(BACKEND)/tests/fixtures/iptables_output/save_default.txt
	multipass exec $(VM) -- sudo iptables -L -v -n      > $(BACKEND)/tests/fixtures/iptables_output/list_verbose.txt
	multipass exec $(VM) -- sudo iptables --version     > $(BACKEND)/tests/fixtures/iptables_output/version.txt
	-multipass exec $(VM) -- sudo iptables -S FWDASH_INPUT 2> $(BACKEND)/tests/fixtures/iptables_output/error_chain_missing.txt
	@echo "Listo. Revisa y anonimiza las IPs antes de commitear."

.PHONY: test-vm
test-vm: ## Tests que necesitan iptables real (ejecutar DENTRO de la VM)
	cd $(BACKEND) && pytest -m requires_iptables

.PHONY: panic
panic: ## Emergencia: elimina las cadenas FWDASH_* y restaura el acceso
	multipass exec $(VM) -- sudo bash /home/ubuntu/app/infra/scripts/panic_reset.sh
