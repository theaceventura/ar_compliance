FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=o365_connector.app
EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "o365_connector.app:create_app()"]
