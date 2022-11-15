SHELL := /bin/bash
.PHONY: help
primary := '\033[1;36m'
err := '\033[0;31m'
bold := '\033[1m'
clear := '\033[0m'

-include .env
export $(shell sed 's/=.*//' .env)
ifndef CI_BUILD_REF
CI_BUILD_REF=local
endif
ifeq ($(CI_BUILD_REF), local)
-include .env.local
export $(shell sed 's/=.*//' .env.local)
endif

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef TRIVIALSCAN_VERSION
TRIVIALSCAN_VERSION=$(shell cat ./src/trivialscan/cli/__main__.py | grep '__version__' | head -n1 | python3 -c "import sys; exec(sys.stdin.read()); print(__version__)")
endif
ifndef TRIVIALSCAN_API_URL
TRIVIALSCAN_API_URL=http://localhost:8080
endif
ifndef APP_ENV
APP_ENV=development
endif
ifndef RUNNER_NAME
RUNNER_NAME=$(shell basename $(shell pwd))
endif

clean: ## cleans python for wheel
	find src -type f -name '*.pyc' -delete 2>/dev/null
	find src -type d -name '__pycache__' -delete 2>/dev/null
	rm -rf build dist **/*.egg-info .pytest_cache rust-query-crlite/target
	rm -f **/*.zip **/*.tgz **/*.gz .coverage

deps: ## install dependancies for development of this project
	python3 -m pip install --disable-pip-version-check -U pip
	python3 -m pip install .

setup: deps ## setup for development of this project
	pre-commit install --hook-type commit-msg --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan > .secrets.baseline )
	yes | detect-secrets audit .secrets.baseline

install: ## Install the package
	python3 -m pip install -U dist/trivialscan-$(TRIVIALSCAN_VERSION)-py3-none-any.whl

reinstall: ## Force install the package
	python3 -m pip install --force-reinstall -U dist/trivialscan-$(TRIVIALSCAN_VERSION)-py3-none-any.whl

install-dev: ## Install the package
	python3 -m pip install --disable-pip-version-check -U pip
	python3 -m pip install -U -r requirements-dev.txt
	python3 -m pip install --force-reinstall --no-cache-dir -e .

pytest: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

test: ## all tests
	pre-commit run --all-files
	coverage report -m

build: ## build wheel file
	rm -f dist/*
	python3 -m build -nxsw

pypi: ## upload to pypi.org
	git tag -f $(TRIVIALSCAN_VERSION)
	git push -u origin --tags -f
	python3 -m twine upload dist/*

tag: ## tag release and push
	git tag -f $(TRIVIALSCAN_VERSION)
	git push -u origin --tags -f

publish: check pypi tag ## upload to pypi.org and push git tags

crlite-musl:  ## Build crlite with musl for AWS Lambda
	rustup target add x86_64-unknown-linux-musl
	(cd rust-query-crlite && cargo build --release --target=x86_64-unknown-linux-musl)
	rm -f rust-query-crlite/target/x86_64-unknown-linux-musl/release/rust-query-crlite
	cp rust-query-crlite/target/x86_64-unknown-linux-musl/release/rust-query-crlite src/trivialscan/vendor/crlite-linux-musl
	chmod a+x src/trivialscan/vendor/crlite-linux-musl

crlite:  ## Build crlite
	(cd rust-query-crlite && cargo build --release)
	rm -f src/trivialscan/vendor/crlite-linux
	cp rust-query-crlite/target/release/rust-query-crlite src/trivialscan/vendor/crlite-linux
	chmod a+x src/trivialscan/vendor/crlite-linux
	./src/trivialscan/vendor/crlite-linux -vvv --db /tmp/.crlite_db/ --update prod x509
	./src/trivialscan/vendor/crlite-linux -vvv --db /tmp/.crlite_db/ https ssllabs.com

local-runner: ## local setup for a gitlab runner
	@docker volume create --name=gitlab-cache 2>/dev/null || true
	docker pull -q docker.io/gitlab/gitlab-runner:latest
	docker build -t $(RUNNER_NAME)/runner:${CI_BUILD_REF} .
	@echo $(shell [ -z "${RUNNER_TOKEN}" ] && echo "RUNNER_TOKEN missing" )
	@docker run -d --rm \
		--name $(RUNNER_NAME) \
		-v "gitlab-cache:/cache:rw" \
		-e RUNNER_TOKEN=${RUNNER_TOKEN} \
		$(RUNNER_NAME)/runner:${CI_BUILD_REF}
	@docker exec -ti $(RUNNER_NAME) gitlab-runner register --non-interactive \
		--tag-list 'trivialscan' \
		--name $(RUNNER_NAME) \
		--request-concurrency 10 \
		--url https://gitlab.com/ \
		--registration-token '$(RUNNER_TOKEN)' \
		--cache-dir '/cache' \
		--executor shell

run-stdin: ## pipe targets from stdin
	cat .$(APP_ENV)/targets.txt | xargs trivial scan -D $(TRIVIALSCAN_API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml --project-name badssl --targets

run-stdin-upload: ## re-upload the piped targets from stdin make target
	trivial scan-upload -D $(TRIVIALSCAN_API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml --results-file .$(APP_ENV)/results/badssl/all.json

run-as-module: ## Using CLI as a python module directly (dev purposes)
	python3 -m trivialscan.cli scan -D $(TRIVIALSCAN_API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml -t ssllabs.com --project-name qualys

run-cli-parallel: ## Leverage defaults using all CPU cores
	trivial scan -D $(TRIVIALSCAN_API_URL) --config-path .$(APP_ENV)/.trivialscan-config.yaml

run-cli-sequential: ## Just use normal python (for clean debugging outputs)
	trivial scan -D $(TRIVIALSCAN_API_URL) --no-multiprocessing --config-path .$(APP_ENV)/.trivialscan-config.yaml

run-info: ## check client details and registration token status
	trivial info -D $(TRIVIALSCAN_API_URL)

run-register: ## registers a new client to retrieve a registration token
	trivial register -D $(TRIVIALSCAN_API_URL)
