# Tier-2 test image: a disposable, root-capable, multi-user host for the
# system tests that mutate users, /opt, /etc, and sudoers. NEVER run these
# tests on a dev machine — that is the whole reason this image exists.
#
# Build from the repo root:  docker build -f docker/Dockerfile -t uvctl-test .
# Run:                       docker run --rm uvctl-test
#
# The primary image is Python 3.12. A version matrix (3.9 / 3.10 for the
# distro-Python + tomli-backport paths) is added by overriding PY_VERSION.
ARG PY_VERSION=3.12
FROM python:${PY_VERSION}-slim

# The `uv` binary serves double duty: it manages this project's venv AND it is
# the tool uvctl drives. Pull the standalone binary from Astral's image.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# System-test prerequisites: sudo + visudo (escalation and sudoers-fragment
# validation), passwd (useradd, for the service + test users).
RUN apt-get update \
    && apt-get install -y --no-install-recommends sudo passwd \
    && rm -rf /var/lib/apt/lists/*

# A non-root user the core-invariant tests execute installed tools as, proving
# "a regular team member with only read/execute access can run the tool".
RUN useradd --create-home --shell /bin/bash tester

WORKDIR /app
COPY . .

# Create the venv and install the package (editable) + dev group. --frozen is
# not used on first build because there is no lock yet; `uv sync` resolves.
RUN uv sync

# Unlock the system tests inside this disposable host only. tests/conftest.py
# refuses to run them without this; a dev host never sets it.
ENV UVCTL_ALLOW_SYSTEM_TESTS=1

# Default: run the system suite. Override the args to run something else, e.g.
#   docker run --rm uvctl-test uv run pytest        # unit + system
CMD ["uv", "run", "pytest", "-m", "system", "-v"]
