#!/usr/bin/env bash
set -e

CONFIG_PATH="/data/options.json"

log() {
    local level="$1"
    shift
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "${timestamp} [${level}] $*"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARNING" "$@"; }
log_error() { log "ERROR" "$@"; }

print_banner_start() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo ""
    echo "================================================================================"
    echo " [${timestamp}] >>> START: OMADA & CLOUDFLARE SSL CERTIFICATE MANAGER <<<"
    echo "================================================================================"
    echo ""
}

print_cycle_start() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo ""
    echo "--------------------------------------------------------------------------------"
    echo " [${timestamp}] >>> STARTING CERTIFICATE ISSUANCE / RENEWAL CYCLE <<<"
    echo "--------------------------------------------------------------------------------"
}

print_cycle_end() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "--------------------------------------------------------------------------------"
    echo " [${timestamp}] >>> FINISHED CERTIFICATE ISSUANCE / RENEWAL CYCLE <<<"
    echo "--------------------------------------------------------------------------------"
    echo ""
}

print_banner_stop() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo ""
    echo "================================================================================"
    echo " [${timestamp}] >>> STOP: OMADA & CLOUDFLARE SSL CERTIFICATE MANAGER <<<"
    echo "================================================================================"
    echo ""
}

# Trap termination signals to show clean stop banner
trap 'print_banner_stop; exit 0' SIGTERM SIGINT SIGHUP

print_banner_start

if [ ! -f "$CONFIG_PATH" ]; then
    log_error "Configuration file $CONFIG_PATH not found!"
    exit 1
fi

# Read options using jq
CLOUDFLARE_API_TOKEN=$(jq --raw-output '.cloudflare_api_token // empty' "$CONFIG_PATH")
LETSENCRYPT_EMAIL=$(jq --raw-output '.letsencrypt_email // empty' "$CONFIG_PATH")
LETSENCRYPT_STAGING=$(jq --raw-output '.letsencrypt_staging // false' "$CONFIG_PATH")
RENEW_INTERVAL_HOURS=$(jq --raw-output '.renew_interval_hours // 12' "$CONFIG_PATH")
COPY_TO_HA_SSL=$(jq --raw-output '.copy_to_ha_ssl // true' "$CONFIG_PATH")
SSL_SUBDIR=$(jq --raw-output '.ssl_subdir // "omada"' "$CONFIG_PATH")
OMADA_ENABLED=$(jq --raw-output '.omada.enabled // false' "$CONFIG_PATH")

# Validate required parameters
if [ -z "$CLOUDFLARE_API_TOKEN" ] || [ "$CLOUDFLARE_API_TOKEN" = "YOUR_CLOUDFLARE_API_TOKEN" ]; then
    log_error "Please specify a valid Cloudflare API Token in the add-on configuration."
    exit 1
fi

if [ -z "$LETSENCRYPT_EMAIL" ] || [ "$LETSENCRYPT_EMAIL" = "admin@yourdomain.com" ]; then
    log_error "Please specify a valid Let's Encrypt email address in the add-on configuration."
    exit 1
fi

# Extract domains
DOMAIN_ARGS=()
DOMAINS_COUNT=$(jq '.domains | length' "$CONFIG_PATH")

if [ "$DOMAINS_COUNT" -eq 0 ]; then
    log_error "At least one domain must be configured in 'domains'!"
    exit 1
fi

PRIMARY_DOMAIN=$(jq --raw-output '.domains[0]' "$CONFIG_PATH")

for i in $(seq 0 $((DOMAINS_COUNT - 1))); do
    DOMAIN=$(jq --raw-output ".domains[$i]" "$CONFIG_PATH")
    DOMAIN_ARGS+=("-d" "$DOMAIN")
    log_info "Registered domain: $DOMAIN"
done

# Prepare persistent storage in /data (survives container restarts)
mkdir -p /data/letsencrypt /data/letsencrypt-work /data/letsencrypt-log /ssl
mkdir -p /etc/letsencrypt

# Bind/symlink or point certbot to persistent /data directories so certs and account are kept
CF_CREDS_FILE="/data/letsencrypt/cloudflare.ini"
echo "dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN" > "$CF_CREDS_FILE"
chmod 600 "$CF_CREDS_FILE"

deploy_certificates() {
    CERT_DIR="/data/letsencrypt/live/${PRIMARY_DOMAIN}"
    FULLCHAIN_FILE="${CERT_DIR}/fullchain.pem"
    PRIVKEY_FILE="${CERT_DIR}/privkey.pem"

    if [ ! -f "$FULLCHAIN_FILE" ] || [ ! -f "$PRIVKEY_FILE" ]; then
        log_error "Certificates not found at $CERT_DIR"
        return 1
    fi

    # Check if certificate files actually changed before triggering redeployments
    local cert_hash
    cert_hash=$(md5sum "$FULLCHAIN_FILE" 2>/dev/null | awk '{print $1}')
    local last_cert_hash=""
    if [ -f "/data/last_deployed_cert_hash" ]; then
        last_cert_hash=$(cat "/data/last_deployed_cert_hash")
    fi

    # 1. Copy to Home Assistant /ssl directory (under a subdirectory to prevent overwriting default HA certs)
    if [ "$COPY_TO_HA_SSL" = "true" ]; then
        DEST_DIR="/ssl"
        if [ -n "$SSL_SUBDIR" ] && [ "$SSL_SUBDIR" != "null" ]; then
            DEST_DIR="/ssl/${SSL_SUBDIR}"
        fi
        log_info "Copying certificates to Home Assistant ${DEST_DIR} directory..."
        mkdir -p "$DEST_DIR"
        cp -f "$FULLCHAIN_FILE" "${DEST_DIR}/fullchain.pem"
        cp -f "$PRIVKEY_FILE" "${DEST_DIR}/privkey.pem"
        if [ -f "${CERT_DIR}/cert.pem" ]; then
            cp -f "${CERT_DIR}/cert.pem" "${DEST_DIR}/cert.pem"
        fi
        if [ -f "${CERT_DIR}/chain.pem" ]; then
            cp -f "${CERT_DIR}/chain.pem" "${DEST_DIR}/chain.pem"
        fi
        log_info "Successfully copied certificates to ${DEST_DIR} directory."
    fi

    # 2. Deploy to Omada Controller if enabled
    if [ "$OMADA_ENABLED" = "true" ]; then
        if [ "$cert_hash" = "$last_cert_hash" ]; then
            log_info "Certificate has not changed since last successful deployment. Skipping Omada upload."
        else
            log_info "Deploying new/renewed certificates to Omada Controller..."
            if python3 /deploy_omada.py "$FULLCHAIN_FILE" "$PRIVKEY_FILE" "$CONFIG_PATH"; then
                echo "$cert_hash" > "/data/last_deployed_cert_hash"
                log_info "Omada certificate deployment successful."
            else
                log_warn "Omada deployment encountered an error."
            fi
        fi
    fi
}

run_certbot() {
    print_cycle_start
    log_info "Checking / Renewing certificates with Certbot..."

    CERTBOT_FLAGS=(
        "certonly"
        "--config-dir" "/data/letsencrypt"
        "--work-dir" "/data/letsencrypt-work"
        "--logs-dir" "/data/letsencrypt-log"
        "--dns-cloudflare"
        "--dns-cloudflare-credentials" "$CF_CREDS_FILE"
        "--dns-cloudflare-propagation-seconds" "30"
        "--non-interactive"
        "--agree-tos"
        "--email" "$LETSENCRYPT_EMAIL"
        "--keep-until-expiring"
        "--expand"
    )

    if [ "$LETSENCRYPT_STAGING" = "true" ]; then
        log_info "Using Let's Encrypt Staging Environment (for testing)."
        CERTBOT_FLAGS+=("--staging")
    fi

    if certbot "${CERTBOT_FLAGS[@]}" "${DOMAIN_ARGS[@]}"; then
        log_info "Certbot execution completed successfully."
        deploy_certificates
    else
        log_error "Certbot encountered an error while requesting/renewing certificates."
    fi

    print_cycle_end
}

# Initial certificate run on startup
run_certbot

# Periodic renewal loop
SLEEP_SECONDS=$(( RENEW_INTERVAL_HOURS * 3600 ))
log_info "Renewal daemon active. Scheduled checks every $RENEW_INTERVAL_HOURS hours."

while true; do
    log_info "Sleeping for $RENEW_INTERVAL_HOURS hours ($SLEEP_SECONDS seconds)..."
    sleep "$SLEEP_SECONDS"
    log_info "Running scheduled certificate renewal check..."
    run_certbot
done
