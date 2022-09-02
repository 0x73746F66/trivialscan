SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
.PHONY: help

.DEFAULT_GOAL := help
ifdef TRIVIALSCAN_VERSION
else
TRIVIALSCAN_VERSION=$(shell cat ./src/trivialscan/cli/__main__.py | grep '__version__' | head -n1 | python3 -c "import sys; exec(sys.stdin.read()); print(__version__)")
endif
ifdef API_URL
else
API_URL="http://127.0.0.1:8000/$(TRIVIALSCAN_VERSION)"
endif
ifdef APP_ENV
else
APP_ENV=development
endif

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

clean: ## cleans python for wheel
	find src -type f -name '*.pyc' -delete 2>/dev/null
	find src -type d -name '__pycache__' -delete 2>/dev/null
	rm -rf build dist **/*.egg-info .pytest_cache rust-query-crlite/target
	rm -f **/*.zip **/*.tgz **/*.gz .coverage

deps: ## install dependancies for development of this project
	pip install --disable-pip-version-check -U pip
	pip install .

setup: deps ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan > .secrets.baseline )
	yes | detect-secrets audit .secrets.baseline

install: ## Install the package
	pip install -U dist/trivialscan-$(TRIVIALSCAN_VERSION)-py2.py3-none-any.whl

reinstall: ## Force install the package
	pip install --force-reinstall -U dist/trivialscan-$(TRIVIALSCAN_VERSION)-py2.py3-none-any.whl

install-dev: ## Install the package
	pip install --disable-pip-version-check -U pip
	pip install -U -r requirements-dev.txt
	pip install --force-reinstall --no-cache-dir -e .

check: ## check build
	python -m twine check dist/*

pytest: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

test: ## all tests
	pre-commit run --all-files
	coverage report -m

build: ## build wheel file
	rm -f dist/*
	python -m build -nxsw

publish: check ## upload to pypi.org
	git tag -f $(TRIVIALSCAN_VERSION)
	git push -u origin --tags -f
	python -m twine upload dist/*

crlite:
	(cd rust-query-crlite && cargo build)
	cp rust-query-crlite/target/debug/rust-query-crlite src/trivialscan/vendor/rust-query-crlite
	chmod a+x src/trivialscan/vendor/rust-query-crlite
	./src/trivialscan/vendor/rust-query-crlite -vvv --db /tmp/.crlite_db/ --update prod x509
	./src/trivialscan/vendor/rust-query-crlite -vvv --db /tmp/.crlite_db/ https ssllabs.com

prerun:
	@echo "TRIVIALSCAN_VERSION $(TRIVIALSCAN_VERSION)"
	@echo "API_URL $(API_URL)"

run-stdin: prerun ## pipe targets from stdin
	cat .$(APP_ENV)/targets.txt | xargs trivial scan -D $(API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml --project-name badssl --targets

run-stdin-upload: prerun ## re-upload the piped targets from stdin make target
	trivial scan-upload -D $(API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml --results-file .$(APP_ENV)/results/badssl/all.json

run-as-module: prerun ## Using CLI as a python module directly (dev purposes)
	python -m trivialscan.cli scan -D $(API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml -t ssllabs.com --project-name qualys

run-cli-parallel: prerun ## Leverage defaults using all CPU cores
	trivial scan -D $(API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml

run-cli-sequential: prerun ## Just use normal python (for clean debugging outputs)
	trivial scan -D $(API_URL) --no-multiprocessing --config-path .$(APP_ENV)/.trivialscan-config.yaml

run-info: ## check client against local API
	trivial info -D $(API_URL)
