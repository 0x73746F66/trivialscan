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
	python -m pip install -U pip
	python -m pip install -U -r requirements.txt

setup: deps ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan > .secrets.baseline )
	yes | detect-secrets audit .secrets.baseline

install: build ## Install the package
	python -m pip install -U dist/trivialscan-$(shell cat ./setup.py | grep '__version__' | sed 's/[_version=", ]//g' | head -n1)-py2.py3-none-any.whl

install-dev: ## Install the package
	python -m pip install -U -r requirements-dev.txt
	python -m pip install --force-reinstall --no-cache-dir -e .

check: ## check build
	python setup.py egg_info
	python setup.py check

pytest: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

test: ## all tests
	pre-commit run --all-files
	coverage report -m

build: check ## build wheel file
	rm -f dist/*
	python -m build -nxsw

publish: ## upload to pypi.org
	git tag -f $(shell cat ./setup.py | grep '__version__' | sed 's/[_version=", ]//g' | head -n1)
	git push -u origin --tags
	python -m twine upload dist/*

crlite:
	(cd vendor/rust-query-crlite && cargo build)
	./vendor/rust-query-crlite/target/debug/rust-query-crlite -vvv --db /tmp/.crlite_db/ --update prod x509
	./vendor/rust-query-crlite/target/debug/rust-query-crlite -vvv --db /tmp/.crlite_db/ https ssllabs.com

run-stdin: ## pipe targets from stdin
	cat .development/targets.txt | xargs python -m trivialscan.cli

run-as-module: ## Using CLI as a python module directly (dev purposes)
	python -m trivialscan.cli ssllabs.com

run-cli-parallel: ## Leverage defaults using all CPU cores
	trivial scan

run-cli-sequential: ## Just use normal python (for clean debugging outputs)
	trivial scan --no-multiprocessing
