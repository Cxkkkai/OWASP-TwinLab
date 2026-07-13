FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /lab

COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY app ./app
COPY run.py ./run.py

EXPOSE 5000

# The host-side Compose mapping is loopback-only. The container must listen on
# its own interface so the mapped port can reach it.
CMD ["flask", "--app", "app:create_app", "run", "--host=0.0.0.0", "--port=5000", "--no-debugger", "--no-reload"]

