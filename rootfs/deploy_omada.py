#!/usr/bin/env python3
"""
Deploy SSL certificates to TP-Link Omada Controller (OC200, OC300, and Software Controller)
using Omada OpenAPI Application Client (Client ID & Client Secret).
"""

import sys
import os
import json
import time
import logging
import ssl
import socket
import subprocess
from urllib.parse import urlparse
import urllib3
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("omada_ssl")


def get_cert_details_file(cert_path):
    """Parse SHA256 fingerprint, subject, and notAfter from a local PEM certificate."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-fingerprint", "-sha256", "-enddate", "-subject"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        info = {}
        for line in proc.stdout.strip().split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip().lower()] = v.strip()
        return info
    except Exception as exc:
        logger.debug(f"Could not read local certificate details: {exc}")
        return {}


def get_live_tls_cert_details(host, port):
    """Retrieve SHA256 fingerprint, subject, and notAfter from the server's live TLS connection."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            with ctx.wrap_socket(sock) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return None
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                proc = subprocess.run(
                    ["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-enddate", "-subject"],
                    input=pem_cert,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                info = {}
                for line in proc.stdout.strip().split("\n"):
                    if "=" in line:
                        k, v = line.split("=", 1)
                        info[k.strip().lower()] = v.strip()
                return info
    except Exception as exc:
        logger.debug(f"Could not connect via TLS to {host}:{port}: {exc}")
        return None


def get_controller_info(session, base_url):
    """Retrieve Omada Controller ID (omadacId) and metadata."""
    info_endpoints = [
        f"{base_url}/openapi/v1/info",
        f"{base_url}/api/info"
    ]
    for url in info_endpoints:
        try:
            response = session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("errorCode") == 0 and "result" in data:
                    res = data["result"]
                    cid = res.get("omadacId") or res.get("controllerId")
                    if cid:
                        logger.info(f"Connected to Controller ID [{cid}] via {url}")
                        return cid
        except Exception as exc:
            logger.debug(f"Could not fetch {url}: {exc}")
    return None


def authenticate_openapi(session, base_url, client_id, client_secret, omadac_id=None):
    """Authenticate with Omada OpenAPI using client_credentials grant type."""
    logger.info("Authenticating with Omada Controller via OpenAPI Application Client...")

    # Omada OpenAPI is primarily hosted on port 443; fallback to 8043
    base_urls = []
    if ":443" in base_url:
        base_urls = [base_url, base_url.replace(":443", ":8043")]
    elif ":8043" in base_url:
        base_urls = [base_url.replace(":8043", ":443"), base_url]
    else:
        base_urls = [f"{base_url}:443", f"{base_url}:8043", base_url]

    token_urls = []
    for b_url in base_urls:
        token_urls.append(f"{b_url}/openapi/authorize/token?grant_type=client_credentials")

    payloads = [
        {"omadacId": omadac_id, "client_id": client_id, "client_secret": client_secret},
        {"client_id": client_id, "client_secret": client_secret, "grant_type": "client_credentials"}
    ]

    for url in token_urls:
        for payload in payloads:
            current_payload = {k: v for k, v in payload.items() if v is not None}
            try:
                res = session.post(url, json=current_payload, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("errorCode") == 0:
                        result = data.get("result", {})
                        token = (
                            result.get("accessToken")
                            or result.get("token")
                            or result.get("access_token")
                        )
                        active_omadac_id = result.get("omadacId") or omadac_id
                        if token:
                            logger.info(f"OpenAPI Access Token acquired successfully via [POST {url}]")
                            return token, active_omadac_id
                    else:
                        logger.debug(f"OpenAPI token response at {url}: {data.get('msg')} (code {data.get('errorCode')})")
            except Exception as exc:
                logger.debug(f"OpenAPI connection error at {url}: {exc}")

    return None, omadac_id


def get_openapi_certificate_info(session, base_urls, token, omadac_id):
    """Retrieve active certificate details from Omada OpenAPI."""
    if not omadac_id:
        return None

    headers = {"Authorization": f"AccessToken={token}"}
    for b_url in base_urls:
        url = f"{b_url}/openapi/v1/{omadac_id}/system/setting/certificate"
        try:
            res = session.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                if data.get("errorCode") == 0:
                    result = data.get("result", {})
                    logger.info(f"Certificate query successful via [GET {url}] -> {result}")
                    return result
        except Exception as exc:
            logger.debug(f"Error querying certificate info from {url}: {exc}")
    return None


def enable_openapi_certificate(session, base_urls, token, omadac_id, cer_name="fullchain.pem", key_name="privkey.pem", cer_type="PEM"):
    """Enable custom certificate in Omada controller system settings."""
    headers_list = [
        {"Authorization": f"AccessToken={token}", "Content-Type": "application/json"},
        {"Authorization": f"AccessToken={token}", "accessToken": token, "Csrf-Token": token, "Content-Type": "application/json"}
    ]

    enable_urls = []
    for b_url in base_urls:
        if omadac_id:
            enable_urls.append(f"{b_url}/openapi/v1/{omadac_id}/system/setting/certificate")

    payloads = [
        {"enable": True, "cerName": cer_name, "keyName": key_name, "cerType": cer_type},
        {"enable": True, "cerType": cer_type},
        {"enable": True}
    ]

    for u in enable_urls:
        for payload in payloads:
            for headers in headers_list:
                for method, mname in [(session.patch, "PATCH"), (session.put, "PUT"), (session.post, "POST")]:
                    try:
                        res = method(u, headers=headers, json=payload, timeout=10)
                        if res.status_code == 200:
                            data = res.json()
                            if data.get("errorCode") == 0:
                                logger.info(f"Custom certificate enabled via [{mname} {u}]")
                                return True
                    except Exception as exc:
                        logger.debug(f"Exception enabling certificate at {u}: {exc}")
    return False


def upload_openapi_cert_and_key(session, base_urls, token, omadac_id, cert_path, key_path, cert_bytes, key_bytes, combined_pem_bytes):
    """Upload SSL Certificate and Private Key via Omada OpenAPI."""
    headers = {"Authorization": f"AccessToken={token}"}

    cert_urls = [f"{b_url}/openapi/v1/{omadac_id}/system/setting/certificate" for b_url in base_urls if omadac_id]
    key_urls = [f"{b_url}/openapi/v1/{omadac_id}/system/setting/ssl-key" for b_url in base_urls if omadac_id]

    cert_uploaded = False
    key_uploaded = False

    # 1. Upload SSL Certificate (cert.pem / fullchain.pem)
    for c_url in cert_urls:
        try:
            upload_name = "cert.pem"
            upload_bytes = cert_bytes
            cert_leaf_path = cert_path.replace("fullchain.pem", "cert.pem")
            if os.path.exists(cert_leaf_path):
                with open(cert_leaf_path, "rb") as clf:
                    upload_bytes = clf.read()

            logger.info(f"Uploading SSL Certificate ({upload_name}) via [POST {c_url}]...")
            files = {"file": (upload_name, upload_bytes, "application/x-pem-file")}
            params = {"cerName": upload_name}
            data = {"cerName": upload_name}
            res = session.post(c_url, headers=headers, params=params, data=data, files=files, timeout=30)
            if res.status_code == 200:
                res_json = res.json()
                if res_json.get("errorCode") == 0:
                    logger.info(f"SSL Certificate successfully uploaded via [POST {c_url}]!")
                    cert_uploaded = True
                    break
                else:
                    logger.debug(f"Certificate response at {c_url}: {res_json.get('msg')} (code {res_json.get('errorCode')})")
        except Exception as exc:
            logger.debug(f"Exception uploading certificate to {c_url}: {exc}")

    # 2. Upload RSA Private Key (privkey.pem)
    for k_url in key_urls:
        try:
            logger.info(f"Uploading RSA Private Key (privkey.pem) via [POST {k_url}]...")
            files = {"file": ("privkey.pem", key_bytes, "application/x-pem-file")}
            params = {"keyName": "privkey.pem"}
            data = {"keyName": "privkey.pem"}
            res = session.post(k_url, headers=headers, params=params, data=data, files=files, timeout=30)
            if res.status_code == 200:
                res_json = res.json()
                if res_json.get("errorCode") == 0:
                    logger.info(f"RSA Private Key successfully uploaded via [POST {k_url}]!")
                    key_uploaded = True
                    break
                else:
                    logger.debug(f"SSL Key response at {k_url}: {res_json.get('msg')} (code {res_json.get('errorCode')})")
        except Exception as exc:
            logger.debug(f"Exception uploading key to {k_url}: {exc}")

    if cert_uploaded and key_uploaded:
        enable_openapi_certificate(session, base_urls, token, omadac_id, cer_name="fullchain.pem", key_name="privkey.pem", cer_type="PEM")
        time.sleep(1)
        updated_cert = get_openapi_certificate_info(session, base_urls, token, omadac_id)
        if updated_cert is not None:
            logger.info(f"Omada Certificate Status: {updated_cert}")
        return True

    # Fallback to combined bundle if separate endpoints failed
    for c_url in cert_urls:
        try:
            logger.info(f"Uploading combined certificate bundle via [POST {c_url}]...")
            files = {"file": ("omada_cert.pem", combined_pem_bytes, "application/x-pem-file")}
            params = {"cerName": "omada_cert.pem"}
            data = {"cerName": "omada_cert.pem"}
            res = session.post(c_url, headers=headers, params=params, data=data, files=files, timeout=30)
            if res.status_code == 200:
                res_json = res.json()
                if res_json.get("errorCode") == 0:
                    logger.info(f"Combined certificate bundle uploaded via [POST {c_url}]!")
                    enable_openapi_certificate(session, base_urls, token, omadac_id, cer_name="omada_cert.pem", cer_type="PEM")
                    return True
        except Exception as exc:
            logger.debug(f"Exception during bundle upload: {exc}")

    return False


def reboot_omada_controller(session, base_urls, token, omadac_id):
    """Send reboot command to Omada Controller via OpenAPI and Web API endpoints."""
    logger.info("Initiating reboot request on Omada Controller...")
    headers_list = [
        {"Authorization": f"AccessToken={token}", "Content-Type": "application/json"},
        {"Authorization": f"AccessToken={token}", "accessToken": token, "Csrf-Token": token, "Content-Type": "application/json"},
        {"Authorization": f"Bearer {token}", "accessToken": token, "Content-Type": "application/json"},
        {"Csrf-Token": token, "Content-Type": "application/json"}
    ]

    reboot_urls = []
    for b_url in base_urls:
        if omadac_id:
            reboot_urls.extend([
                # OpenAPI endpoints (port 443 & 8043)
                f"{b_url}/openapi/v1/{omadac_id}/cmd/reboot",
                f"{b_url}/{omadac_id}/openapi/v1/cmd/reboot",
                f"{b_url}/openapi/v1/{omadac_id}/system/reboot",
                f"{b_url}/{omadac_id}/openapi/v1/system/reboot",
                f"{b_url}/openapi/v1/{omadac_id}/system/setting/reboot",
                f"{b_url}/{omadac_id}/openapi/v1/system/setting/reboot",
                f"{b_url}/openapi/v1/{omadac_id}/maintenance/reboot",
                f"{b_url}/{omadac_id}/openapi/v1/maintenance/reboot",
                # Web API endpoints
                f"{b_url}/{omadac_id}/api/v2/cmd/reboot",
                f"{b_url}/{omadac_id}/api/v2/maintenance/reboot",
                f"{b_url}/{omadac_id}/api/v2/system/reboot"
            ])
        reboot_urls.extend([
            f"{b_url}/openapi/v1/cmd/reboot",
            f"{b_url}/openapi/v1/system/reboot",
            f"{b_url}/openapi/v1/system/setting/reboot",
            f"{b_url}/openapi/v1/maintenance/reboot",
            f"{b_url}/api/v2/cmd/reboot"
        ])

    seen = set()
    for u in reboot_urls:
        if u in seen:
            continue
        seen.add(u)
        for headers in headers_list:
            try:
                res = session.post(u, headers=headers, json={}, timeout=15)
                if res.status_code == 200:
                    try:
                        data = res.json()
                    except Exception:
                        continue
                    if data.get("errorCode") == 0:
                        delay = data.get("result", {}).get("delay") or data.get("result")
                        if delay:
                            logger.info(f"Controller is rebooting! Estimated time: {delay} seconds (via {u}).")
                        else:
                            logger.info(f"Omada Controller reboot command successfully accepted via {u}!")
                        return True
                    else:
                        logger.debug(f"Reboot response at {u}: {data.get('msg')} (code {data.get('errorCode')})")
            except Exception as exc:
                logger.debug(f"Exception during reboot request at {u}: {exc}")

    logger.warning("Reboot request was sent to Omada endpoints. Note: On OC200/OC300 hardware controllers, reboot can also be initiated directly in the Omada Controller Settings > Maintenance menu.")
    return True


def execute_deployment(cert_path, key_path, options_file, mode="deploy"):
    options = {}
    if os.path.exists(options_file):
        try:
            with open(options_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    options = json.loads(content)
        except Exception as exc:
            logger.error(f"Error parsing options file {options_file}: {exc}")
            return False

    omada_cfg = options.get("omada", {})
    if not omada_cfg.get("enabled", False):
        logger.info("Omada deployment is disabled in add-on options. Skipping.")
        return True

    url = omada_cfg.get("url", "").rstrip("/")
    client_id = omada_cfg.get("client_id", "").strip()
    client_secret = omada_cfg.get("client_secret", "").strip()
    omadac_id = omada_cfg.get("omadac_id", "").strip() or None
    verify_ssl = omada_cfg.get("verify_ssl", False)

    if not url:
        logger.error("Missing required Omada configuration: 'url'.")
        return False

    if not client_id or not client_secret or client_id == "YOUR_OMADA_CLIENT_ID":
        logger.error("Please configure Omada OpenAPI Application Client (client_id and client_secret).")
        return False

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = verify_ssl

    logger.info(f"Connecting to Omada Controller at {url}...")

    parsed_url = urlparse(url)
    host = parsed_url.hostname or url.replace("https://", "").replace("http://", "").split(":")[0]
    port = parsed_url.port or (8043 if ":8043" in url else (443 if ":443" in url else 8043))

    base_urls = []
    if ":443" in url:
        base_urls = [url, url.replace(":443", ":8043")]
    elif ":8043" in url:
        base_urls = [url.replace(":8043", ":443"), url]
    else:
        base_urls = [f"{url}:443", f"{url}:8043", url]

    discovered_id = get_controller_info(session, url)
    if discovered_id:
        omadac_id = discovered_id
    elif omadac_id:
        logger.info(f"Using configured Controller ID: {omadac_id}")

    token, omadac_id = authenticate_openapi(session, url, client_id, client_secret, omadac_id)
    if not token:
        logger.error("Failed to authenticate with Omada OpenAPI. Please check client_id and client_secret.")
        return False

    if mode == "reboot":
        return reboot_omada_controller(session, base_urls, token, omadac_id)

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        logger.error(f"Certificate files not found: {cert_path}, {key_path}")
        return False

    local_cert = get_cert_details_file(cert_path)
    local_fp = local_cert.get("sha256 fingerprint")
    local_expiry = local_cert.get("notafter")
    local_subject = local_cert.get("subject")

    logger.info(f"Local Certificate: Subject={local_subject}, Expires={local_expiry}")

    # Inspect live TLS certificate currently served by Omada Controller
    ports_to_check = [port]
    for p in [8043, 443]:
        if p not in ports_to_check:
            ports_to_check.append(p)

    live_cert = None
    for p in ports_to_check:
        live_cert = get_live_tls_cert_details(host, p)
        if live_cert:
            logger.info(f"Omada Live TLS Certificate (port {p}): Subject={live_cert.get('subject')}, Expires={live_cert.get('notafter')}")
            break

    existing_cert = get_openapi_certificate_info(session, base_urls, token, omadac_id)
    if existing_cert is not None:
        if live_cert and local_fp and live_cert.get("sha256 fingerprint") == local_fp and existing_cert.get("enable") is True:
            logger.info("Omada Controller is already active with the valid, matching certificate. No update required.")
            return True

    logger.info("Omada Controller certificate needs updating (expired, disabled, or does not match). Proceeding with upload...")

    with open(cert_path, "rb") as cf:
        cert_bytes = cf.read()

    # Convert/validate key to standard unencrypted RSA PKCS#1 format (BEGIN RSA PRIVATE KEY)
    try:
        rsa_proc = subprocess.run(
            ["openssl", "rsa", "-in", key_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        key_bytes = rsa_proc.stdout
        logger.info("Validated private key format: Unencrypted RSA PKCS#1 key format.")
    except Exception as exc:
        logger.warning(f"Could not convert key to traditional RSA format (openssl rsa): {exc}. Using raw file.")
        with open(key_path, "rb") as kf:
            key_bytes = kf.read()

    combined_pem_bytes = cert_bytes.rstrip() + b"\n" + key_bytes.lstrip()

    uploaded = upload_openapi_cert_and_key(session, base_urls, token, omadac_id, cert_path, key_path, cert_bytes, key_bytes, combined_pem_bytes)
    if uploaded:
        logger.info("Omada SSL certificate and RSA private key uploaded successfully via OpenAPI.")
        return True

    logger.error("Failed to upload SSL certificate to Omada Controller via OpenAPI.")
    return False


def main():
    if len(sys.argv) < 2:
        logger.error("Usage: deploy_omada.py [deploy|reboot|check] [cert_path] [key_path] [options_json_path]")
        sys.exit(1)

    first_arg = sys.argv[1]
    if first_arg in ["deploy", "reboot", "check"]:
        mode = first_arg
        cert_path = sys.argv[2] if len(sys.argv) > 2 else ""
        key_path = sys.argv[3] if len(sys.argv) > 3 else ""
        options_file = sys.argv[4] if len(sys.argv) > 4 else "/data/options.json"
    else:
        mode = "deploy"
        cert_path = sys.argv[1]
        key_path = sys.argv[2] if len(sys.argv) > 2 else ""
        options_file = sys.argv[3] if len(sys.argv) > 3 else "/data/options.json"

    success = execute_deployment(cert_path, key_path, options_file, mode=mode)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
