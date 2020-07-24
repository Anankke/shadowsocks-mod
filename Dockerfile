FROM alpine:3.9
MAINTAINER cieons<cieonsers@gmail.com>

ENV NODE_ID=0                    \
    NS1=8.8.4.4                  \
    NS2=1.0.0.1                  \
    ANTISSATTACK=0               \
    MU_SUFFIX=microsoft.com           \
    MU_REGEX=%5m%id.%suffix      \
    API_INTERFACE=modwebapi      \
    WEBAPI_URL=https://zhaoj.in  \
    WEBAPI_TOKEN=glzjin          \
    MYSQL_HOST=127.0.0.1         \
    MYSQL_PORT=3306              \
    MYSQL_USER=ss                \
    MYSQL_PASS=ss                \
    MYSQL_DB=shadowsocks         

COPY . /root/shadowsocks-mod
WORKDIR /root/shadowsocks-mod

RUN apk add --no-cache                          \
        curl                                    \
        libintl                                 \
        python3-dev                             \
        libsodium-dev                           \
        openssl-dev                             \
        udns-dev                                \
        mbedtls-dev                             \
        pcre-dev                                \
        libev-dev                               \
        libtool                                 \
        libffi-dev                           && \
    apk add --no-cache --virtual .build-deps    \
        tar                                     \
        make                                    \
        gettext                                 \
        py3-pip                                 \
        autoconf                                \
        automake                                \
        build-base                              \
        linux-headers                        && \
    ln -s /usr/bin/python3 /usr/bin/python   && \
    ln -s /usr/bin/pip3    /usr/bin/pip      && \
    cp /usr/bin/envsubst  /usr/local/bin/    && \
    pip install --upgrade pip                && \
    pip install -r requirements.txt          && \
    rm -rf ~/.cache && touch /etc/hosts.deny && \
    apk del --purge .build-deps

CMD envsubst < apiconfig.py > userapiconfig.py && \
    envsubst < config.json > user-config.json  && \
    if [ $NS1 != 8.8.4.4 -a $NS2 = 1.0.0.1 ];then echo -e "$NS1 53">/root/shadowsocks/dns.conf ; else echo -e "$NS1 53\n$NS2 53">/root/shadowsocks/dns.conf ; fi && \
    python server.py