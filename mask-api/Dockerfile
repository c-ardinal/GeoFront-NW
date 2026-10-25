FROM python:3.12-slim
WORKDIR /app
COPY mask_api.py .
RUN python mask_api.py --selftest
USER nobody
EXPOSE 8000
CMD ["python", "-u", "mask_api.py"]
