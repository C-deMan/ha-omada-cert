ARG BUILD_FROM
FROM $BUILD_FROM

# Install dependencies for Certbot and Omada Controller API interaction
RUN \
    apk add --no-cache \
        openssl \
        ca-certificates \
        bash \
        jq \
        curl \
        libffi-dev \
        openssl-dev \
        gcc \
        musl-dev \
        python3-dev \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        certbot \
        certbot-dns-cloudflare \
        requests \
        urllib3 \
    && apk del gcc musl-dev python3-dev libffi-dev openssl-dev

# Copy application scripts
COPY rootfs /

WORKDIR /

RUN chmod a+x /run.sh /deploy_omada.py

CMD [ "/run.sh" ]
