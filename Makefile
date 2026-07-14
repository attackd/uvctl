# uvctl developer entry points. Two test tiers:
#   - unit tests run here on the host, in the uv venv, and mutate nothing
#   - system tests mutate users/dirs/sudoers and run ONLY in the container
.PHONY: sync test test-unit lint fmt docs image test-system test-all clean

IMAGE ?= uvctl-test

sync:            ## Create/refresh the venv from pyproject (dev group included)
	uv sync

test: test-unit  ## Default `make test` is the host-safe unit tier

test-unit: sync  ## Tier 1: host-safe unit tests (no root, no system mutation)
	uv run pytest

lint: sync       ## Ruff lint incl. D (docstring) rules
	uv run ruff check .

fmt: sync        ## Ruff autoformat
	uv run ruff format .

docs: sync       ## Build the Sphinx docs (requires the [docs] extra)
	uv run --extra docs sphinx-build -W docs docs/_build

image:           ## Build the tier-2 container image
	docker build -f docker/Dockerfile -t $(IMAGE) .

test-system: image  ## Tier 2: system tests inside the disposable container
	docker run --rm $(IMAGE)

test-all: image  ## Both tiers inside the container (unit + system)
	docker run --rm $(IMAGE) uv run pytest

clean:
	rm -rf .venv .pytest_cache .ruff_cache docs/_build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
