FROM python:3.12-slim
WORKDIR /app
COPY demo_gen.py .
# the demo devices come from the device drivers (compose: additional context "drivers" = ./drivers)
COPY --from=drivers . /drivers
RUN python demo_gen.py --selftest
USER nobody
EXPOSE 9116
CMD ["python", "-u", "demo_gen.py"]
