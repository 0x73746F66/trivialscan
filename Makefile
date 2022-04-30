SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

deps: ## install dependancies for development of this project
	pip install -U pip
	pip install -U -r requirements-dev.txt
	pip install -e .

setup: deps ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan > .secrets.baseline )
	detect-secrets audit .secrets.baseline

install: ## Install the package
	pip install -U dist/trivialscan-$(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')-py2.py3-none-any.whl

check: ## check build
	python setup.py egg_info
	python setup.py check

test: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

build: check ## build wheel file
	rm -f dist/*
	python -m build -nxsw

publish: ## upload to pypi.org
	git tag -f $(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')
	git push -u origin --tags
	python -m twine upload dist/*

test-local: ## Prettier test outputs
	pre-commit run --all-files
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

run-json: ## www.trivialsec.com
	@python src/trivialscan/cli/__init__.py www.trivialsec.com -O trivialscan_www.trivialsec.com.json

run-valid: ## google.com
	@python src/trivialscan/cli/__init__.py ssllabs.com

run-expired: ## expired.badssl.com
	@python src/trivialscan/cli/__init__.py expired.badssl.com

run-selfsigned: ## self-signed.badssl.com
	@python src/trivialscan/cli/__init__.py self-signed.badssl.com

run-invalid-hostname: ## wrong.host.badssl.com no-common-name.badssl.com
	@python src/trivialscan/cli/__init__.py wrong.host.badssl.com no-common-name.badssl.com

run-untrusted: ## untrusted.root.badssl.com
	@python src/trivialscan/cli/__init__.py untrusted.root.badssl.com

run-revoked: ## no-subject.badssl.com
	@python src/trivialscan/cli/__init__.py no-subject.badssl.com

run-broken: ## revoked.badssl.com
	@python src/trivialscan/cli/__init__.py revoked.badssl.com

run-invalid-hpkp: ## pinning-test.badssl.com
	@python src/trivialscan/cli/__init__.py pinning-test.badssl.com

run-incomplete-chain: ## incomplete-chain.badssl.com sha1-intermediate.badssl.com
	@python src/trivialscan/cli/__init__.py incomplete-chain.badssl.com sha1-intermediate.badssl.com

run-missing-ct: ## no-sct.badssl.com invalid-expected-sct.badssl.com
	@python src/trivialscan/cli/__init__.py no-sct.badssl.com invalid-expected-sct.badssl.com

run-weak: ## null.badssl.com cbc.badssl.com rc4-md5.badssl.com rc4.badssl.com 3des.badssl.com static-rsa.badssl.com sha1-2016.badssl.com
	@python src/trivialscan/cli/__init__.py null.badssl.com cbc.badssl.com rc4-md5.badssl.com rc4.badssl.com 3des.badssl.com -H static-rsa.badssl.com -H sha1-2016.badssl.com

run-deprecated-tls: ## tls-v1-0.badssl.com tls-v1-1.badssl.com
	@python src/trivialscan/cli/__init__.py -H tls-v1-0.badssl.com -p 1010 -H tls-v1-1.badssl.com -p 1011

run-known-pwnd: ## superfish.badssl.com edellroot.badssl.com dsdtestprovider.badssl.com preact-cli.badssl.com webpack-dev-server.badssl.com
	@python src/trivialscan/cli/__init__.py -H superfish.badssl.com -H edellroot.badssl.com -H dsdtestprovider.badssl.com -H preact-cli.badssl.com -H webpack-dev-server.badssl.com
