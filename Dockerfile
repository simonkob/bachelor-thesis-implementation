FROM python:3.9.1

COPY main.py .
COPY app.py .
COPY requirements.txt .
COPY *config.ini .

RUN pip install -r requirements.txt

CMD [ "python" , "./main.py" ]