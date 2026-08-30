#!/usr/bin/env bash
set -e

CONFIG_PATH="/data/options.json"

# Set timezone: Check Supervisor API, user config, or TZ env
setup_timezone() {
    local detected_tz=""

    # 1. Check user configured timezone in options.json
    if [ -f "$CONFIG_PATH" ]; then
        detected_tz=$(jq --raw-output '.timezone // empty' "$CONFIG_PATH" 2>/dev/null || true)
    fi

    # 2. If not specified, query Home Assistant Supervisor Core API
    if [ -z "$detected_tz" ] && [ -n "$SUPERVISOR_TOKEN" ]; then
        detected_tz=$(curl -s -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" \
            -H "Content-Type: application/json" \
            http://supervisor/core/info 2>/dev/null | jq --raw-output '.data.time_zone // empty' 2>/dev/null || true)
    fi

    # 3. Fallback to existing TZ env variable if present
    if [ -z "$detected_tz" ] && [ -n "$TZ" ]; then
        detected_tz="$TZ"
    fi

    # Apply detected timezone if valid tzdata file exists
    if [ -n "$detected_tz" ] && [ -f "/usr/share/zoneinfo/${detected_tz}" ]; then
        export TZ="$detected_tz"
        cp "/usr/share/zoneinfo/${detected_tz}" /etc/localtime 2>/dev/null || true
        echo "$detected_tz" > /etc/timezone 2>/dev/null || true
    elif [ -n "$detected_tz" ]; then
        export TZ="$detected_tz"
    fi
}

setup_timezone

# Detect Add-on Version
get_addon_version() {
    local ver=""
    if [ -f "/etc/addon_config.yaml" ]; then
        ver=$(grep "^version:" /etc/addon_config.yaml 2>/dev/null | awk -F'"' '{print $2}' || true)
    fi
    if [ -z "$ver" ] && [ -n "$SUPERVISOR_TOKEN" ]; then
        ver=$(curl -s -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" \
            -H "Content-Type: application/json" \
            http://supervisor/addons/self/info 2>/dev/null | jq --raw-output '.data.version // empty' 2>/dev/null || true)
    fi
    if [ -z "$ver" ]; then
        ver="1.1.3"
    fi
    echo "$ver"
}

ADDON_VERSION=$(get_addon_version)

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
    echo " [${timestamp}] >>> START: OMADA & CLOUDFLARE SSL CERTIFICATE MANAGER v${ADDON_VERSION} <<<"
    echo "================================================================================"
    echo ""
}

print_cycle_start() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo ""
    echo "--------------------------------------------------------------------------------"
    echo " [${timestamp}] >>> STARTING CERTIFICATE ISSUANCE / RENEWAL CYCLE (v${ADDON_VERSION}) <<<"
    echo "--------------------------------------------------------------------------------"
}

print_cycle_end() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "--------------------------------------------------------------------------------"
    echo " [${timestamp}] >>> FINISHED CERTIFICATE ISSUANCE / RENEWAL CYCLE (v${ADDON_VERSION}) <<<"
    echo "--------------------------------------------------------------------------------"
    echo ""
}

print_banner_stop() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo ""
    echo "================================================================================"
    echo " [${timestamp}] >>> STOP: OMADA & CLOUDFLARE SSL CERTIFICATE MANAGER v${ADDON_VERSION} <<<"
    echo "================================================================================"
    echo ""
}

# Trap termination signals to show clean stop banner and stop background servers
cleanup() {
    if [ -n "$WEB_SERVER_PID" ] && kill -0 "$WEB_SERVER_PID" 2>/dev/null; then
        kill "$WEB_SERVER_PID" 2>/dev/null || true
    fi
    print_banner_stop
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

print_banner_start

# Tee output to persistent log file in /data
mkdir -p /data/letsencrypt /data/letsencrypt-work /data/letsencrypt-log /ssl
touch /data/addon.log

# Start Ingress Web Server in background
log_info "Starting Ingress Web Dashboard on port 8099..."
python3 /web_server.py &
WEB_SERVER_PID=$!

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
        log_info "Checking and synchronizing certificates with Omada Controller..."
        if python3 /deploy_omada.py deploy "$FULLCHAIN_FILE" "$PRIVKEY_FILE" "$CONFIG_PATH"; then
            log_info "Omada certificate check and synchronization completed."
        else
            log_warn "Omada deployment encountered an error."
        fi
    fi
}

run_certbot() {
    print_cycle_start
    log_info "Checking / Renewing certificates with Certbot (2048-bit RSA)..."

    CERT_DIR="/data/letsencrypt/live/${PRIMARY_DOMAIN}"
    PRIVKEY_FILE="${CERT_DIR}/privkey.pem"

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
        "--cert-name" "$PRIMARY_DOMAIN"
        "--key-type" "rsa"
        "--rsa-key-size" "2048"
        "--keep-until-expiring"
        "--expand"
    )

    # If an existing key exists but is not an unencrypted RSA key (e.g. default ECDSA), force renewal to RSA
    if [ -f "$PRIVKEY_FILE" ]; then
        if ! openssl rsa -in "$PRIVKEY_FILE" -check -noout >/dev/null 2>&1; then
            log_warn "Existing certificate is not an unencrypted RSA key (Omada requires unencrypted RSA). Forcing renewal with 2048-bit RSA..."
            CERTBOT_FLAGS+=("--force-renewal")
        fi
    fi

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

# Initial certificate run on startup/restart
run_certbot

# Scheduled check loop: Supports every day / daily, weekly, monthly
SCHEDULE_FREQ=$(jq --raw-output '.schedule_frequency // "daily"' "$CONFIG_PATH" 2>/dev/null | tr '[:upper:]' '[:lower:]')
SCHEDULE_TIME=$(jq --raw-output '.schedule_time // "03:00"' "$CONFIG_PATH" 2>/dev/null)

log_info "Scheduled checks active. Frequency: ${SCHEDULE_FREQ} at ${SCHEDULE_TIME}."

LAST_SCHEDULED_RUN=""

while true; do
    sleep 25
    CURRENT_TIME=$(date "+%H:%M")
    CURRENT_DAY_OF_WEEK=$(date "+%u") # 1..7 (Monday..Sunday, 7 = Sunday)
    CURRENT_DAY_OF_MONTH=$(date "+%d") # 01..31
    CURRENT_SLOT="$(date '+%Y-%m-%d')_${CURRENT_TIME}"

    TIME_MATCH=false
    if [ "$CURRENT_TIME" = "$SCHEDULE_TIME" ]; then
        TIME_MATCH=true
    fi

    SHOULD_RUN=false
    if [ "$TIME_MATCH" = "true" ] && [ "$LAST_SCHEDULED_RUN" != "$CURRENT_SLOT" ]; then
        case "$SCHEDULE_FREQ" in
            "every day"|"daily")
                SHOULD_RUN=true
                ;;
            "weekly")
                # Run once a week on Sunday (day 7)
                if [ "$CURRENT_DAY_OF_WEEK" -eq 7 ]; then
                    SHOULD_RUN=true
                fi
                ;;
            "monthly")
                # Run on the 1st of every month
                if [ "$CURRENT_DAY_OF_MONTH" = "01" ] || [ "$CURRENT_DAY_OF_MONTH" = "1" ]; then
                    SHOULD_RUN=true
                fi
                ;;
            *)
                SHOULD_RUN=true
                ;;
        esac

        if [ "$SHOULD_RUN" = "true" ]; then
            LAST_SCHEDULED_RUN="$CURRENT_SLOT"
            log_info "Scheduled check time reached (${SCHEDULE_FREQ} at ${CURRENT_TIME}). Running certificate check..."
            run_certbot
        fi
    fi
done
