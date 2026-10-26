FROM python:3.12-slim
# dumpcap (wireshark-common, Debian trixie, held to the 4.4 series): writes packets only, never dissects them
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireshark-common=4.4.* \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY capture.py .
RUN python capture.py --selftest
ENV PYTHONUNBUFFERED=1
# root inside the container, but with only NET_RAW / NET_ADMIN (compose.yaml drops every other capability)
CMD ["python", "-u", "capture.py"]
