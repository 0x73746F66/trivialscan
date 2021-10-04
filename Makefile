SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
APP_NAME = trivialsec

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help


install-deps: ## setup for development of this project
	pip install -q -U pip setuptools wheel semgrep pylint pytest build twine

install: build ## Install the package
	pip install -q -U --no-cache-dir --force-reinstall dist/tls_verify-*-py2.py3-none-any.whl

check: ## check build
	python3 setup.py check

build: check ## build wheel file
	rm -f dist/*
	python3 -m build

publish: build ## upload to pypi.org
	git tag $(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')
	git push -u origin --tags
	python3 -m twine upload dist/*

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

test-all: semgrep-sast-ci pylint-ci ## Run all CI tests

run-valid:
	python src/main.py -H google.com

run-invalid-expired:
	python src/main.py -H expired.badssl.com

run-invalid-selfsigned:
	python src/main.py -H self-signed.badssl.com

run-invalid-hostname:
	python src/main.py -H wrong.host.badssl.com

run-invalid-untrusted:
	python src/main.py -H untrusted.root.badssl.com

run-invalid-revoked:
	python src/main.py -H revoked.badssl.com --sni

run-invalid-hpkp:
	python src/main.py -H pinning-test.badssl.com --sni
