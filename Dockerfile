FROM python:3.11-slim

WORKDIR /app

COPY main.py .
COPY start.sh .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN chmod +x start.sh
RUN mkdir -p /data

CMD ["sh", "start.sh"]
