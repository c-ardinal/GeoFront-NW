FROM python:3.12-slim
WORKDIR /app
COPY mask_api.py pcap_api.py pcap_filter.py evidence.py correlate.py ./
RUN python mask_api.py --selftest
# this tool's version in evidence exports: given at build time (compose: OBS_COMMIT), never read from .git at runtime
ARG OBS_COMMIT=unknown
ENV OBS_COMMIT=${OBS_COMMIT}
LABEL org.opencontainers.image.revision=${OBS_COMMIT}
# pcap uploads: a fresh named volume mounted here takes over this owner (nobody), so uploads are writable
RUN mkdir -p /uploads && chown nobody:nogroup /uploads && chmod 0755 /uploads
USER nobody
EXPOSE 8000
CMD ["python", "-u", "mask_api.py"]
