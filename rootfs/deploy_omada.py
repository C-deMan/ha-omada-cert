#!/usr/bin/env python3
"""
Deploy SSL certificates to TP-Link Omada Controller (OC200, OC300, and Software Controller)
using Omada OpenAPI Application Client (Client ID & Client Secret) or fallback credentials.
Supports Omada Controller v4.x and v5.x.
"""

import sys
import os
import json
import time
import hmac
import hashlib
import logging
import urllib3
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("omada_ssl")


def get_controller_info(session, base_url):
    """Retrieve Omada Controller ID (omadacId) and metadata."""
    info_endpoints = [
        f"{base_url}/api/info",
        f"{base_url}/openapi/v1/info"
    ]
    for url in info_endpoints:
        try:
            response = session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get("errorCode") == 0 and "result" in data:
                    res = data["result"]
                    return res.get("omadacId") or res.get("controllerId")
        except Exception as exc:
            logger.debug(f"Could not fetch {url}: {exc}")
    return None


def authenticate_openapi(session, base_url, client_id, client_secret, omadac_id=None):
    """Authenticate with Omada OpenAPI using Client ID (App ID / Client ID) and Client Secret (or signature)."""
    logger.info("Authenticating with Omada Controller via OpenAPI Application Client...")

    timestamp = int(time.time() * 1000)
    
    # Generate signature if needed: sign(client_id + timestamp + client_secret)
    raw_sign_str = f"{client_id}{timestamp}{client_secret}"
    signature = hmac.new(client_secret.encode("utf-8"), raw_sign_str.encode("utf-8"), hashlib.sha256).hexdigest()
    md5_sign = hashlib.md5(raw_sign_str.encode("utf-8")).hexdigest()

    # Omada Controller OpenAPI standard payload formats across different controller versions
    payloads = [
        # Standard Omada OpenAPI v1 payload
        {"omadacId": omadac_id, "appId": client_id, "secret": client_secret},
        {"omadacId": omadac_id, "client_id": client_id, "client_secret": client_secret},
        {"omadacId": omadac_id, "appKey": client_id, "appSecret": client_secret},
        # Omada signed token request
        {"omadacId": omadac_id, "appId": client_id, "timestamp": timestamp, "sign": signature},
        {"omadacId": omadac_id, "appId": client_id, "timestamp": timestamp, "sign": md5_sign},
        # Without omadacId inside JSON body
        {"appId": client_id, "secret": client_secret},
        {"client_id": client_id, "client_secret": client_secret},
        {"appKey": client_id, "appSecret": client_secret}
    ]

    urls = [
        f"{base_url}/openapi/v1/token",
        f"{base_url}/openapi/authorize/token",
        f"{base_url}/api/v2/openapi/token"
    ]
    if omadac_id:
        urls = [
            f"{base_url}/openapi/v1/token?omadacId={omadac_id}",
            f"{base_url}/{omadac_id}/openapi/v1/token",
            f"{base_url}/openapi/authorize/token?omadacId={omadac_id}",
            f"{base_url}/{omadac_id}/api/v2/openapi/token",
            f"{base_url}/api/v2/openapi/token?omadacId={omadac_id}"
        ] + urls

    for url in urls:
        for payload in payloads:
            # Clean up None values
            current_payload = {k: v for k, v in payload.items() if v is not None}

            try:
                # Also try query params style for GET or POST
                res = session.post(url, json=current_payload, timeout=15)
                
                try:
                    data = res.json()
                except Exception:
                    continue

                if data.get("errorCode") == 0:
                    result = data.get("result", {})
                    token = (
                        result.get("accessToken")
                        or result.get("token")
                        or result.get("access_token")
                    )
                    active_omadac_id = result.get("omadacId") or omadac_id
                    if token:
                        logger.info(f"Successfully obtained OpenAPI access token from Omada Controller using {url}!")
                        return token, active_omadac_id, "openapi"
                else:
                    msg = data.get("msg") or data.get("message")
                    code = data.get("errorCode")
                    logger.debug(f"OpenAPI attempt at {url} with {list(current_payload.keys())} returned {code}: {msg}")
            except Exception as exc:
                logger.debug(f"OpenAPI connection error at {url}: {exc}")

    # Also test GET method with params (supported in some Omada versions)
    for url in [f"{base_url}/openapi/v1/token", f"{base_url}/openapi/authorize/token"]:
        try:
            params = {"omadacId": omadac_id, "appId": client_id, "secret": client_secret}
            res = session.get(url, params={k: v for k, v in params.items() if v is not None}, timeout=15)
            if res.status_code == 200:
                data = res.json()
                if data.get("errorCode") == 0:
                    result = data.get("result", {})
                    token = result.get("accessToken") or result.get("token")
                    if token:
                        logger.info(f"Successfully obtained OpenAPI access token via GET from {url}!")
                        return token, omadac_id, "openapi"
        except Exception:
            pass

    return None, omadac_id, None


def authenticate_user_pass(session, base_url, username, password, omadac_id=None):
    """Authenticate with Omada Controller using username & password."""
    logger.info("Authenticating with Omada Controller via username/password...")
    login_urls = []
    if omadac_id:
        login_urls.append(f"{base_url}/{omadac_id}/api/v2/login")
    login_urls.append(f"{base_url}/api/v2/login")

    payload = {
        "username": username,
        "password": password
    }

    token = None
    active_omadac_id = omadac_id

    for url in login_urls:
        try:
            logger.info(f"Attempting login to {url}...")
            res = session.post(url, json=payload, timeout=15)
            if res.status_code == 200:
                data = res.json()
                if data.get("errorCode") == 0:
                    result = data.get("result", {})
                    token = result.get("token")
                    if not active_omadac_id:
                        active_omadac_id = result.get("omadacId")
                    logger.info("Successfully authenticated with Omada Controller.")
                    return token, active_omadac_id, "session"
                else:
                    logger.warning(f"Login failed at {url}: {data.get('msg')} (code {data.get('errorCode')})")
        except Exception as exc:
            logger.warning(f"Connection error while logging in at {url}: {exc}")

    return None, None, None


def upload_ssl_certificate(session, base_url, token, omadac_id, auth_type, cert_path, key_path):
    """Upload SSL Certificate and Private Key to Omada Controller."""
    if not os.path.exists(cert_path):
        logger.error(f"Certificate file not found: {cert_path}")
        return False
    if not os.path.exists(key_path):
        logger.error(f"Key file not found: {key_path}")
        return False

    headers_list = []
    if auth_type == "openapi":
        headers_list.append({
            "Authorization": f"AccessToken={token}",
            "accessToken": token,
            "Csrf-Token": token
        })
        headers_list.append({
            "Authorization": f"Bearer {token}",
            "accessToken": token
        })
    else:
        headers_list.append({
            "Csrf-Token": token
        })

    upload_urls = []
    if omadac_id:
        upload_urls.append(f"{base_url}/openapi/v1/{omadac_id}/maintenance/ssl")
        upload_urls.append(f"{base_url}/{omadac_id}/api/v2/maintenance/ssl")
    upload_urls.append(f"{base_url}/openapi/v1/maintenance/ssl")
    upload_urls.append(f"{base_url}/api/v2/maintenance/ssl")

    for url in upload_urls:
        for headers in headers_list:
            try:
                logger.info(f"Uploading SSL certificate and key to {url}...")
                with open(cert_path, "rb") as cert_file, open(key_path, "rb") as key_file:
                    files = {
                        "certFile": ("fullchain.pem", cert_file, "application/x-pem-file"),
                        "keyFile": ("privkey.pem", key_file, "application/x-pem-file")
                    }
                    data = {
                        "type": 1
                    }
                    res = session.post(url, headers=headers, data=data, files=files, timeout=30)

                if res.status_code == 200:
                    res_json = res.json()
                    if res_json.get("errorCode") == 0:
                        logger.info("SSL Certificate successfully uploaded and installed on Omada Controller!")
                        return True
                    else:
                        logger.warning(f"Omada response at {url}: {res_json.get('msg')} (code {res_json.get('errorCode')})")
                else:
                    logger.debug(f"HTTP status {res.status_code} during upload to {url}")
            except Exception as exc:
                logger.debug(f"Exception during SSL upload to {url}: {exc}")

    logger.error("Failed to upload SSL certificate to Omada Controller across all available endpoints.")
    return False


def logout_omada(session, base_url, token, omadac_id, auth_type):
    """Gracefully log out or revoke session if needed."""
    if auth_type != "session":
        return
    headers = {"Csrf-Token": token}
    logout_urls = []
    if omadac_id:
        logout_urls.append(f"{base_url}/{omadac_id}/api/v2/logout")
    logout_urls.append(f"{base_url}/api/v2/logout")

    for url in logout_urls:
        try:
            session.post(url, headers=headers, timeout=10)
        except Exception:
            pass


def main():
    if len(sys.argv) < 3:
        logger.error("Usage: deploy_omada.py <cert_path> <key_path> [options_json_path]")
        sys.exit(1)

    cert_path = sys.argv[1]
    key_path = sys.argv[2]
    options_file = sys.argv[3] if len(sys.argv) > 3 else "/data/options.json"

    if not os.path.exists(options_file):
        logger.error(f"Options file not found: {options_file}")
        sys.exit(1)

    with open(options_file, "r") as f:
        options = json.load(f)

    omada_cfg = options.get("omada", {})
    if not omada_cfg.get("enabled", False):
        logger.info("Omada deployment is disabled in add-on options. Skipping.")
        sys.exit(0)

    url = omada_cfg.get("url", "").rstrip("/")
    client_id = omada_cfg.get("client_id", "").strip()
    client_secret = omada_cfg.get("client_secret", "").strip()
    omadac_id = omada_cfg.get("omadac_id", "").strip() or None
    username = omada_cfg.get("username", "").strip()
    password = omada_cfg.get("password", "").strip()
    verify_ssl = omada_cfg.get("verify_ssl", False)

    if not url:
        logger.error("Missing required Omada configuration: 'url'.")
        sys.exit(1)

    has_openapi = bool(client_id and client_secret and client_id != "YOUR_OMADA_CLIENT_ID")
    has_userpass = bool(username and password and password != "your_omada_password")

    if not has_openapi and not has_userpass:
        logger.error("Please configure either Omada OpenAPI credentials (client_id & client_secret) or username & password.")
        sys.exit(1)

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = verify_ssl

    logger.info(f"Connecting to Omada Controller at {url}...")
    discovered_id = get_controller_info(session, url)
    if discovered_id:
        logger.info(f"Discovered Omada Controller ID: {discovered_id}")
        omadac_id = discovered_id
    elif omadac_id:
        logger.info(f"Using manually configured Omada Controller ID: {omadac_id}")

    token = None
    auth_type = None

    if has_openapi:
        token, omadac_id, auth_type = authenticate_openapi(session, url, client_id, client_secret, omadac_id)
        if not token:
            logger.error("Failed to authenticate with Omada OpenAPI. Please check your client_id, client_secret, and omadac_id.")
            if has_userpass:
                logger.info("Falling back to username/password authentication...")
                token, omadac_id, auth_type = authenticate_user_pass(session, url, username, password, omadac_id)

    elif has_userpass:
        token, omadac_id, auth_type = authenticate_user_pass(session, url, username, password, omadac_id)

    if not token:
        logger.error("Failed to authenticate with Omada Controller.")
        sys.exit(1)

    success = upload_ssl_certificate(session, url, token, omadac_id, auth_type, cert_path, key_path)
    logout_omada(session, url, token, omadac_id, auth_type)

    if not success:
        sys.exit(1)

    logger.info("Omada SSL deployment completed successfully.")


if __name__ == "__main__":
    main()
