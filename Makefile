SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

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
	pip install -U dist/trivialscan-$(shell cat ./src/trivialscan/cli/__main__.py | grep '__version__' | sed 's/[_version=", ]//g' | head -n1)-py2.py3-none-any.whl

reinstall: ## Force install the package
	pip install --force-reinstall -U dist/trivialscan-$(shell cat ./src/trivialscan/cli/__main__.py | grep '__version__' | sed 's/[_version=", ]//g' | head -n1)-py2.py3-none-any.whl

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
	git tag -f $(shell cat ./src/trivialscan/cli/__main__.py | grep '__version__' | sed 's/[_version=", ]//g' | head -n1)
	git push -u origin --tags -f
	python -m twine upload dist/*

crlite:
	(cd rust-query-crlite && cargo build)
	cp rust-query-crlite/target/debug/rust-query-crlite src/trivialscan/vendor/rust-query-crlite
	chmod a+x src/trivialscan/vendor/rust-query-crlite
	./src/trivialscan/vendor/rust-query-crlite -vvv --db /tmp/.crlite_db/ --update prod x509
	./src/trivialscan/vendor/rust-query-crlite -vvv --db /tmp/.crlite_db/ https ssllabs.com

run-stdin: ## pipe targets from stdin
	cat .development/targets.txt | xargs trivialscan.cli

run-as-module: ## Using CLI as a python module directly (dev purposes)
	python -m trivialscan.cli scan -t ssllabs.com

run-cli-parallel: ## Leverage defaults using all CPU cores
	trivial scan

run-cli-sequential: ## Just use normal python (for clean debugging outputs)
	trivial scan --no-multiprocessing

run-info: ## check client against local API
	trivial info -D http://localhost:8000/3.0.0rc3/
