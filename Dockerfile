FROM python:3.10-slim

WORKDIR /app
COPY . .

RUN pip install --upgrade pip \
 && pip install -r requirements.txt

CMD ["gunicorn", "app:app", "--bind=0.0.0.0:8000"]
