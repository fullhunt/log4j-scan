FROM python:3-alpine

WORKDIR /app

COPY requirements.txt requirements.txt

RUN apk add gcc g++ make libffi-dev openssl-dev
RUN pip3 install -r requirements.txt

COPY . .

ENTRYPOINT ["python", "log4j-scan.py" ]
