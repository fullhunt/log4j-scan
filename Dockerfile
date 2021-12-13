FROM python:3.7

RUN apt update
RUN mkdir /src
RUN mkdir /data
ADD . /src

RUN ls -lah /src && sleep 4
RUN cd /src && pip install -r requirements.txt

ENTRYPOINT [ "python", "/src/log4j-scan.py" ]