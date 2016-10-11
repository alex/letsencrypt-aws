FROM python:2.7-slim

# This can be bumped every time you need to force an apt refresh
ENV LAST_UPDATE 6

RUN apt-get update && apt-get upgrade -y
RUN apt-get update && apt-get install -y build-essential libffi-dev libssl-dev git

WORKDIR /app/

RUN python -m pip install virtualenv
RUN python -m virtualenv .venv
COPY requirements.txt ./
RUN .venv/bin/pip install -r requirements.txt
COPY letsencrypt-aws.py ./
RUN chmod 644 letsencrypt-aws.py

USER nobody

ENTRYPOINT [".venv/bin/python", "letsencrypt-aws.py"]
CMD ["update-certificates"]
