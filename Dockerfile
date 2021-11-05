FROM python:3.9.2-alpine

COPY . /app
WORKDIR /app

RUN apk add --no-cache \
        gcc \
        libsodium-dev \
        libffi-dev \
        openssl-dev && \
    apk add --no-cache --virtual .build \
        libc-dev \
        rust \
        cargo && \
    pip install --no-cache-dir -r requirements.txt && \
    cp docker-apiconfig.py userapiconfig.py && \
    apk del --purge .build

CMD ["server.py"]
ENTRYPOINT ["python"]