FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ARG CACHEBUST=1
COPY main.py .
COPY start.sh .
RUN chmod +x start.sh

RUN mkdir -p /data

CMD ["sh", "start.sh"]
