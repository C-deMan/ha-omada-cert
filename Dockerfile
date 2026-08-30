ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:latest
FROM $BUILD_FROM

# Install dependencies for Certbot, Python, and Omada Controller API interaction
RUN \
    apk add --no-cache \
        openssl \
        ca-certificates \
        tzdata \
        bash \
        jq \
        curl \
        python3 \
        py3-pip \
        py3-cryptography \
        py3-requests \
        py3-urllib3 \
        libffi-dev \
        openssl-dev \
        gcc \
        musl-dev \
        python3-dev \
    && pip install --no-cache-dir --upgrade pip --break-system-packages \
    && pip install --no-cache-dir --break-system-packages \
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
