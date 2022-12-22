FROM node:alpine

COPY json_exporter/* /opt/app/

COPY requirements.txt /opt/app/

COPY config.yaml /opt/app/

RUN apk update && apk upgrade && \
    apk add --update --no-cache py3-pip gcc python3-dev musl-dev && \
    pip3 install --upgrade pip && \
    pip3 install -r /opt/app/requirements.txt && \
    rm -rf /var/cache/apk/*

WORKDIR /opt/app/

ENTRYPOINT /usr/bin/python3 -u main.py config.yaml
