FROM python:3.12-alpine

ENV DEBUG false

RUN mkdir /application
COPY . /application

WORKDIR /application

COPY requirements.txt /application

COPY . /application

RUN apk add --no-cache tzdata bluez bluez-libs sudo bluez-deprecated git                              && \
    apk add --no-cache --virtual build-dependencies git bluez-dev musl-dev make gcc glib-dev musl-dev && \
    ln -s /config.yaml ./config.yaml                                                                  && \
    pip install --no-cache-dir -r requirements.txt                                                    && \
    pip install --no-cache-dir `./gateway.py -r all`                                                  && \
    apk del build-dependencies

COPY ./start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/bin/sh", "-c", "/start.sh"]
