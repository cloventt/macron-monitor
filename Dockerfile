FROM python:3.12-alpine

RUN python -m pip install poetry

WORKDIR /app
COPY . .

RUN python -m poetry install

ENTRYPOINT python -m poetry run python macron_monitor/MacronMonitor.py
