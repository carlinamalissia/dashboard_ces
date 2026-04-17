FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# cache-bust: 2026-04-17-v2
COPY main.py .
COPY start.sh .
RUN chmod +x start.sh

RUN mkdir -p /data

CMD ["sh", "start.sh"]
