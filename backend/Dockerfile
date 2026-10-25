FROM mcr.microsoft.com/playwright/python:v1.51.0-noble

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ensure Chromium binary is linked
RUN python3 -m playwright install chromium

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "python3 -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
