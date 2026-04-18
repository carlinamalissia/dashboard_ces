FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# cache-bust: 2026-04-18-v1
COPY . .
RUN mkdir -p /data
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
