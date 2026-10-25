FROM python:3.12-slim
WORKDIR /app
COPY relay.py .
RUN python relay.py --selftest
# its own uid: relay.json (the notification secrets, 0600) belongs to it alone; Prometheus / Alertmanager (nobody) mount
# the same generated volume and cannot read it. tools/notify.py writes the file for this uid (RELAY_UID).
RUN groupadd --system --gid 10095 relay && useradd --system --uid 10095 --gid 10095 --no-create-home --shell /usr/sbin/nologin relay
USER 10095:10095
EXPOSE 9095
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
CMD ["python", "relay.py"]
