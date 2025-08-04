FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir flask

EXPOSE 80

CMD ["python", "scannerbait.py"]
