FROM python:2.7-slim

# This can be bumped every time you need to force an apt refresh
ENV LAST_UPDATE 1

RUN apt-get update
RUN apt-get upgrade
RUN apt-get install -y build-essential libffi-dev libssl-dev

WORKDIR /app/

RUN python -m virtualenv .venv
COPY requirements.txt .
RUN .venv/bin/pip install -r requirements.txt
COPY letsencrypt-aws.py .

USER nobody

CMD .venv/bin/python letsencrypt-aws.py
