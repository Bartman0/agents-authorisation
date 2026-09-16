FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY identity.py db.py spicedb.py authz.py agent.py ./

ENTRYPOINT ["python", "agent.py"]
