FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir requests==2.32.3
COPY init.py ./

CMD ["python", "init.py"]
