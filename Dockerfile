# Ref: https://devguide.python.org/#branchstatus
FROM python:3.10-slim-bullseye

RUN useradd -ms /bin/bash appuser
USER appuser
WORKDIR /app

COPY --chown=appuser:appuser requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

ENV PATH="/home/appuser/.local/bin:${PATH}"

COPY --chown=appuser:appuser ./ ./

ENTRYPOINT ["python", "log4j-scan.py" ]