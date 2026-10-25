FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
# PyYAML: the device inventory is a hand-edited YAML file; the stdlib has no YAML parser.
RUN pip install --no-cache-dir --only-binary=:all: PyYAML==6.0.3
WORKDIR /app
COPY obs.py notify.py ./
RUN python -c "import ast; [ast.parse(open(f, encoding='utf-8').read()) for f in ('obs.py', 'notify.py')]"
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
ENTRYPOINT ["python", "/app/obs.py"]
CMD ["help"]
