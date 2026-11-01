FROM python:3.15-slim
# tshark from Debian trixie, held to the 4.4 series (security updates come in on rebuild; the version is shown
# by `ping` and in the analysis screen). --no-install-recommends: no GUI, no extcap helpers.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark=4.4.* \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY analyzer.py .
# field classes for the display filter policy and the masking of detail trees, from this very tshark
RUN python analyzer.py --build-fields
COPY --from=demo demo-home.pcap /demo/demo-home.pcap
RUN useradd --system --uid 10001 --home-dir /tmp --shell /usr/sbin/nologin analyzer \
 && su -s /bin/sh analyzer -c "HOME=/tmp python analyzer.py --selftest"
USER 10001
ENV PYTHONUNBUFFERED=1 HOME=/tmp
CMD ["python", "-u", "analyzer.py"]
