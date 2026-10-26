FROM python:3.12-slim
# maxminddb: reader for the DB-IP Lite .mmdb files (MaxMind DB format); binary wheels for amd64 and arm64
RUN pip install --no-cache-dir --only-binary=:all: maxminddb==3.2.0
WORKDIR /app
COPY flowd.py .
RUN python flowd.py --selftest
USER nobody
ENV PYTHONUNBUFFERED=1
EXPOSE 9100
CMD ["python", "-u", "flowd.py"]
