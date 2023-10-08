FROM python:3.10-alpine

ENV DEBUG false

RUN mkdir application
WORKDIR /application

COPY requirements.txt /application

COPY . /application

RUN apk add --no-cache tzdata bluez bluez-libs sudo bluez-deprecated && \
    apk add --no-cache --virtual build-dependencies git bluez-dev musl-dev make gcc glib-dev musl-dev && \
    ln -s /config.yaml ./config.yaml                                 && \
    pip install -r requirements.txt                                  && \
    pip install `./gateway.py -r all`                                                                 && \
    apk del build-dependencies

COPY ./start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/bin/sh", "-c", "/start.sh"]
