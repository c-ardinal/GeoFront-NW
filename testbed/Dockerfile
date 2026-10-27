FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --no-deps --only-binary=:all: -r requirements.txt
COPY device.py notifymock.py ./
# the syslog fixtures of the device drivers (compose: additional context "drivers" = ./drivers)
COPY --from=drivers . /drivers
RUN python device.py --selftest
USER nobody
CMD ["python", "-u", "device.py"]
