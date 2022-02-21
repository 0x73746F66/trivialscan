SHELL := /bin/bash
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

setup: ## setup for development of this project
	python -m pip install --progress-bar off -U pip
	python -m pip install --progress-bar off -U -r dev-requirements.txt
	python -m pip install --progress-bar off -e .

install: build ## Install the package
	python -m pip install -U --progress-bar off --no-cache-dir --force-reinstall dist/trivialscan-$(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')-py2.py3-none-any.whl

check: ## check build
	python setup.py egg_info
	python setup.py check

test: install test-only ## run unit tests with coverage

test-only: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

build: check ## build wheel file
	rm -f dist/*
	python -m build -nx

publish: ## upload to pypi.org
	git tag -f $(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')
	git push -u origin --tags
	python -m twine upload dist/*

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

test-all: semgrep-sast-ci pylint-ci ## Run all CI tests

run-json: ## www.trivialsec.com
	@python src/main.py www.trivialsec.com -O trivialscan_www.trivialsec.com.json

run-valid: ## google.com
	@python src/main.py -H google.com

run-expired: ## expired.badssl.com
	@python src/main.py -H expired.badssl.com

run-selfsigned: ## self-signed.badssl.com
	@python src/main.py -H self-signed.badssl.com

run-invalid-hostname: ## wrong.host.badssl.com no-common-name.badssl.com
	@python src/main.py -H wrong.host.badssl.com
	@python src/main.py -H no-common-name.badssl.com

run-untrusted: ## untrusted.root.badssl.com
	@python src/main.py -H untrusted.root.badssl.com

run-revoked: ## no-subject.badssl.com
	@python src/main.py -H no-subject.badssl.com

run-broken: ## revoked.badssl.com
	@python src/main.py -H revoked.badssl.com

run-invalid-hpkp: ## pinning-test.badssl.com
	@python src/main.py -H pinning-test.badssl.com

run-incomplete-chain: ## incomplete-chain.badssl.com sha1-intermediate.badssl.com
	@python src/main.py -H incomplete-chain.badssl.com
	@python src/main.py -H sha1-intermediate.badssl.com

run-missing-ct: ## no-sct.badssl.com invalid-expected-sct.badssl.com
	@python src/main.py -H no-sct.badssl.com
	@python src/main.py -H invalid-expected-sct.badssl.com

run-weak: ## null.badssl.com cbc.badssl.com rc4-md5.badssl.com rc4.badssl.com 3des.badssl.com static-rsa.badssl.com sha1-2016.badssl.com
	@python src/main.py -H null.badssl.com
	@python src/main.py -H cbc.badssl.com
	@python src/main.py -H rc4-md5.badssl.com
	@python src/main.py -H rc4.badssl.com
	@python src/main.py -H 3des.badssl.com
	@python src/main.py -H static-rsa.badssl.com
	@python src/main.py -H sha1-2016.badssl.com

run-deprecated-tls: ## tls-v1-0.badssl.com tls-v1-1.badssl.com
	@python src/main.py -H tls-v1-0.badssl.com -p 1010
	@python src/main.py -H tls-v1-1.badssl.com -p 1011

run-known-pwnd: ## superfish.badssl.com edellroot.badssl.com dsdtestprovider.badssl.com preact-cli.badssl.com webpack-dev-server.badssl.com
	@python src/main.py -H superfish.badssl.com
	@python src/main.py -H edellroot.badssl.com
	@python src/main.py -H dsdtestprovider.badssl.com
	@python src/main.py -H preact-cli.badssl.com
	@python src/main.py -H webpack-dev-server.badssl.com
