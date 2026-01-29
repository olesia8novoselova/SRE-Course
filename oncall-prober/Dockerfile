FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY exporter.py /app/exporter.py
RUN pip install --no-cache-dir requests environs prometheus_client
EXPOSE 9081
CMD ["python", "-u", "exporter.py"]