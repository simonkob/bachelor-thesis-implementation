# syntax=docker/dockerfile:1

FROM python:latest

WORKDIR /home/app

ENV IS_IN_DOCKER=yes

WORKDIR /home/app

ENV IS_IN_DOCKER=yes

COPY main.py .
COPY app.py .
COPY requirements.txt .
COPY users_algo.py .

RUN pip install -r requirements.txt

CMD [ "python" , "./main.py" ]