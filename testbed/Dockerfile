FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --no-deps --only-binary=:all: -r requirements.txt
COPY device.py notifymock.py ./
# the syslog fixtures of the device drivers (compose: additional context "drivers" = ./drivers)
COPY --from=drivers . /drivers
RUN python device.py --selftest
USER nobody
CMD ["python", "-u", "device.py"]
