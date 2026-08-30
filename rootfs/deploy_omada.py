#!/usr/bin/env python3
"""
Deploy SSL certificates to TP-Link Omada Controller (OC200, OC300, and Software Controller).
Supports Omada Controller v4.x and v5.x.
"""

import sys
import os
import json
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
    try:
        url = f"{base_url}/api/info"
        response = session.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if data.get("errorCode") == 0 and "result" in data:
                return data["result"].get("omadacId") or data["result"].get("controllerId")
    except Exception as exc:
        logger.debug(f"Could not fetch /api/info: {exc}")
    return None


def login_omada(session, base_url, username, password, omadac_id=None):
    """Authenticate with Omada Controller and obtain session token."""
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
                    return token, active_omadac_id
                else:
                    logger.warning(f"Login failed at {url}: {data.get('msg')} (code {data.get('errorCode')})")
        except Exception as exc:
            logger.warning(f"Connection error while logging in at {url}: {exc}")

    return None, None


def upload_ssl_certificate(session, base_url, token, omadac_id, cert_path, key_path):
    """Upload SSL Certificate and Private Key to Omada Controller."""
    headers = {
        "Csrf-Token": token
    }

    upload_urls = []
    if omadac_id:
        upload_urls.append(f"{base_url}/{omadac_id}/api/v2/maintenance/ssl")
    upload_urls.append(f"{base_url}/api/v2/maintenance/ssl")

    if not os.path.exists(cert_path):
        logger.error(f"Certificate file not found: {cert_path}")
        return False
    if not os.path.exists(key_path):
        logger.error(f"Key file not found: {key_path}")
        return False

    for url in upload_urls:
        try:
            logger.info(f"Uploading SSL certificate and key to {url}...")
            with open(cert_path, "rb") as cert_file, open(key_path, "rb") as key_file:
                files = {
                    "certFile": ("fullchain.pem", cert_file, "application/x-pem-file"),
                    "keyFile": ("privkey.pem", key_file, "application/x-pem-file")
                }
                # Form data indicating PEM type upload
                data = {
                    "type": 1
                }
                res = session.post(url, headers=headers, data=data, files=files, timeout=30)

            if res.status_code == 200:
                res_json = res.json()
                if res_json.get("errorCode") == 0:
                    logger.info("SSL Certificate successfully uploaded to Omada Controller!")
                    return True
                else:
                    logger.error(f"Omada rejected SSL certificate: {res_json.get('msg')} (code {res_json.get('errorCode')})")
            else:
                logger.error(f"HTTP error {res.status_code} during SSL upload: {res.text}")
        except Exception as exc:
            logger.error(f"Exception during SSL upload to {url}: {exc}")

    return False


def logout_omada(session, base_url, token, omadac_id):
    """Gracefully log out of Omada Controller."""
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
    username = omada_cfg.get("username", "")
    password = omada_cfg.get("password", "")
    verify_ssl = omada_cfg.get("verify_ssl", False)

    if not url or not username or not password:
        logger.error("Missing required Omada configuration (url, username, or password).")
        sys.exit(1)

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = verify_ssl

    logger.info(f"Connecting to Omada Controller at {url}...")
    omadac_id = get_controller_info(session, url)
    if omadac_id:
        logger.info(f"Discovered Omada Controller ID: {omadac_id}")

    token, active_omadac_id = login_omada(session, url, username, password, omadac_id)
    if not token:
        logger.error("Failed to authenticate with Omada Controller. Check credentials & URL.")
        sys.exit(1)

    success = upload_ssl_certificate(session, url, token, active_omadac_id, cert_path, key_path)
    logout_omada(session, url, token, active_omadac_id)

    if not success:
        sys.exit(1)

    logger.info("Omada SSL deployment completed successfully.")


if __name__ == "__main__":
    main()
