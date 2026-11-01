FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913
# PyYAML: the device inventory is a hand-edited YAML file; the stdlib has no YAML parser.
# argon2-cffi (+ its pinned dependencies, binary wheels for amd64 and arm64): argon2id password hashes for Authelia's
# users file (tools user); the stdlib has no argon2.
RUN pip install --no-cache-dir --only-binary=:all: PyYAML==6.0.3 argon2-cffi==25.1.0 argon2-cffi-bindings==26.1.0 cffi==2.1.1 pycparser==3.12
WORKDIR /app
COPY obs.py notify.py capture.py auth.py doctor.py ./
# the selftest reads a few repository files (compose: additional context "repo"); bound for this step only, not kept
RUN --mount=type=bind,from=repo,source=README.md,target=/selftest/README.md     --mount=type=bind,from=repo,source=config.example,target=/selftest/config.example     --mount=type=bind,from=repo,source=drivers,target=/selftest/drivers     --mount=type=bind,from=repo,source=snmp,target=/selftest/snmp     OBS_WORK=/selftest OBS_CONFIG=/tmp/cfg OBS_GENERATED=/tmp/gen OBS_VOLUMES=/tmp/vol python obs.py --selftest
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
ENTRYPOINT ["python", "/app/obs.py"]
CMD ["help"]
