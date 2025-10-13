FROM python:3.13-slim

ENV HTTPSHOW_VERSION=0.3.2
ENV VERSION=0.3.2
ENV SUMMARY="HTTPShow: Simple HTTP request inspector with OIDC support"
ENV TZ=Europe/Zurich
ENV HOME=/home/httpshow
ENV PATH=/home/httpshow/.local/bin:/code/bin:/usr/bin:$PATH

LABEL name="airlock/httpshow" \
    summary="$SUMMARY" \
    description="$SUMMARY" \
    version="$HTTPSHOW_VERSION" \
    maintainer="Urs Zurbuchen <urs.zurbuchen@ergon.ch>" \
    release="1" \
    io.k8s.description="$SUMMARY" \
    io.k8s.display-name="httpshow"

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt \
    && find /home

COPY ./app /code/app
COPY ./samples ${HOME}

CMD ["uvicorn", "app.main:app", "--port", "8000", "--host", "0.0.0.0"]
