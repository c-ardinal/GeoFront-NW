FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
# PyYAML: the device inventory is a hand-edited YAML file; the stdlib has no YAML parser.
# argon2-cffi (+ its pinned dependencies, binary wheels for amd64 and arm64): argon2id password hashes for Authelia's
# users file (tools user); the stdlib has no argon2.
RUN pip install --no-cache-dir --only-binary=:all: PyYAML==6.0.3 argon2-cffi==25.1.0 argon2-cffi-bindings==26.1.0 cffi==2.1.1 pycparser==3.12
WORKDIR /app
COPY obs.py notify.py capture.py auth.py ./
# the selftest reads a few repository files (compose: additional context "repo"); bound for this step only, not kept
RUN --mount=type=bind,from=repo,source=README.md,target=/selftest/README.md     --mount=type=bind,from=repo,source=.env.example,target=/selftest/.env.example     --mount=type=bind,from=repo,source=snmp,target=/selftest/snmp     --mount=type=bind,from=repo,source=dashboards,target=/selftest/dashboards     OBS_WORK=/selftest OBS_GENERATED=/tmp/gen OBS_VOLUMES=/tmp/vol python obs.py --selftest
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
ENTRYPOINT ["python", "/app/obs.py"]
CMD ["help"]
