# End-to-end test environment, based on the target system (Debian 13 trixie).
# Run with tests/e2e/run.sh: the container must be privileged to use loop devices.
# clamav-daemon is started by the tests with a test-only signature database.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv libmagic1 clamav-daemon \
        dosfstools exfatprogs e2fsprogs mount util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tests ./tests
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -e ".[dev]"

CMD ["/venv/bin/pytest", "-m", "e2e", "-v", "tests/e2e"]
