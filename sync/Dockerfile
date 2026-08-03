FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY spicedb_client.py fixtures.py bootstrap.py sync.py relctl.py check.py ./

# Overridden per-service in docker-compose (bootstrap vs sync).
CMD ["python", "sync.py"]
