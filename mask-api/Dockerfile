FROM python:3.15-slim
WORKDIR /app
COPY mask_api.py pcap_api.py pcap_filter.py evidence.py correlate.py trend_api.py logsearch.py ./
# the evidence export's time budget for this selftest only (not kept in the image): a QEMU-emulated release build
# (linux/arm64 on amd64, .github/docker-bake.hcl) is ~10x slower than a native one
ARG SELFTEST_EVIDENCE_BUDGET=60
RUN EVIDENCE_TIME_BUDGET=${SELFTEST_EVIDENCE_BUDGET} python mask_api.py --selftest
# this tool's version in evidence exports: given at build time (compose: OBS_COMMIT), never read from .git at runtime
ARG OBS_COMMIT=unknown
ENV OBS_COMMIT=${OBS_COMMIT}
LABEL org.opencontainers.image.revision=${OBS_COMMIT}
# pcap uploads: a fresh named volume mounted here takes over this owner (nobody), so uploads are writable
RUN mkdir -p /uploads && chown nobody:nogroup /uploads && chmod 0755 /uploads
USER nobody
EXPOSE 8000
CMD ["python", "-u", "mask_api.py"]
