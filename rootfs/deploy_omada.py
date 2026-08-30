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
    """Authenticate with Omada OpenAPI according to TP-Link OpenAPI Specification (Client Credentials Mode)."""
    logger.info("Authenticating with Omada Controller via OpenAPI Application Client...")

    # Prioritize port 443 where Omada OpenAPI Interface is hosted
    base_urls = []
    if ":443" in base_url:
        base_urls = [base_url, base_url.replace(":443", ":8043")]
    elif ":8043" in base_url:
        base_urls = [base_url.replace(":8043", ":443"), base_url, base_url.replace(":8043", "")]
    else:
        base_urls = [f"{base_url}:443", f"{base_url}:8043", base_url]

    candidate_endpoints = []
    for b_url in base_urls:
        candidate_endpoints.extend([
            f"{b_url}/openapi/authorize/token?grant_type=client_credentials",
            f"{b_url}/openapi/v1/token?grant_type=client_credentials",
            f"{b_url}/openapi/authorize/token",
            f"{b_url}/openapi/v1/token"
        ])
        if omadac_id:
            candidate_endpoints.extend([
                f"{b_url}/openapi/authorize/token?grant_type=client_credentials&omadacId={omadac_id}",
                f"{b_url}/openapi/authorize/token?grant_type=client_credentials&omadac_id={omadac_id}",
                f"{b_url}/{omadac_id}/openapi/authorize/token?grant_type=client_credentials",
                f"{b_url}/{omadac_id}/openapi/v1/token?grant_type=client_credentials"
            ])

    # De-duplicate endpoints
    seen = set()
    primary_urls = []
    for ep in candidate_endpoints:
        if ep not in seen:
            seen.add(ep)
            primary_urls.append(ep)

    payloads = [
        # Official TP-Link OpenAPI format
        {"omadacId": omadac_id, "client_id": client_id, "client_secret": client_secret},
        {"omadac_id": omadac_id, "client_id": client_id, "client_secret": client_secret},
        {"omadacId": omadac_id, "appId": client_id, "secret": client_secret},
        {"omadacId": omadac_id, "appKey": client_id, "appSecret": client_secret},
        # Without omadacId inside JSON body
        {"client_id": client_id, "client_secret": client_secret, "grant_type": "client_credentials"},
        {"client_id": client_id, "client_secret": client_secret},
        {"appId": client_id, "secret": client_secret}
    ]

    for url in primary_urls:
        for payload in payloads:
            current_payload = {k: v for k, v in payload.items() if v is not None}
            try:
                res = session.post(url, json=current_payload, timeout=10)
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
                        logger.info(f"Successfully obtained OpenAPI access token from Omada Controller via {url}!")
                        return token, active_omadac_id, "openapi"
                else:
                    msg = data.get("msg") or data.get("message")
                    code = data.get("errorCode")
                    logger.debug(f"OpenAPI attempt at {url} returned [{code}]: {msg}")
            except Exception as exc:
                logger.debug(f"OpenAPI connection error at {url}: {exc}")

    return None, omadac_id, None


def authenticate_user_pass(session, base_url, username, password, omadac_id=None):
    """Authenticate with Omada Controller using username & password."""
    logger.info("Authenticating with Omada Controller via username/password...")

    base_urls = [base_url]
    if ":8043" in base_url:
        base_urls.append(base_url.replace(":8043", ":443"))
        base_urls.append(base_url.replace(":8043", ""))
    elif ":443" in base_url:
        base_urls.append(base_url.replace(":443", ":8043"))
    else:
        base_urls.append(f"{base_url}:8043")
        base_urls.append(f"{base_url}:443")

    login_urls = []
    for b_url in base_urls:
        if omadac_id:
            login_urls.append(f"{b_url}/{omadac_id}/api/v2/login")
        login_urls.append(f"{b_url}/api/v2/login")

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


def get_openapi_certificate_info(session, base_urls, token, omadac_id):
    """Retrieve existing certificate info from Omada OpenAPI."""
    if not omadac_id:
        return None

    headers = {"Authorization": f"AccessToken={token}"}
    for b_url in base_urls:
        urls = [
            f"{b_url}/openapi/v1/{omadac_id}/system/setting/certificate",
            f"{b_url}/{omadac_id}/openapi/v1/system/setting/certificate"
        ]
        for url in urls:
            try:
                res = session.get(url, headers=headers, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("errorCode") == 0:
                        return data.get("result", {})
            except Exception as exc:
                logger.debug(f"Error querying certificate info from {url}: {exc}")
    return None


def get_openapi_certificate_info(session, base_urls, token, omadac_id):
    """Retrieve existing certificate info from Omada OpenAPI."""
    if not omadac_id:
        return None

    headers = {"Authorization": f"AccessToken={token}"}
    for b_url in base_urls:
        urls = [
            f"{b_url}/openapi/v1/{omadac_id}/system/setting/certificate",
            f"{b_url}/{omadac_id}/openapi/v1/system/setting/certificate"
        ]
        for url in urls:
            try:
                res = session.get(url, headers=headers, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("errorCode") == 0:
                        return data.get("result", {})
            except Exception as exc:
                logger.debug(f"Error querying certificate info from {url}: {exc}")
    return None


def upload_openapi_cert_and_key(session, base_urls, token, omadac_id, cert_bytes, key_bytes, combined_pem_bytes, pfx_bytes):
    """Upload SSL Certificate and Key via official Omada OpenAPI endpoints."""
    headers_list = [
        {"Authorization": f"AccessToken={token}"},
        {"Authorization": f"AccessToken={token}", "accessToken": token, "Csrf-Token": token},
        {"Authorization": f"Bearer {token}", "accessToken": token}
    ]

    existing_cert = get_openapi_certificate_info(session, base_urls, token, omadac_id)
    if existing_cert is not None:
        logger.info(f"Current Omada certificate status before upload: {existing_cert}")

    cert_urls = []
    key_urls = []
    for b_url in base_urls:
        if omadac_id:
            cert_urls.extend([
                f"{b_url}/openapi/v1/{omadac_id}/system/setting/certificate",
                f"{b_url}/{omadac_id}/openapi/v1/system/setting/certificate"
            ])
            key_urls.extend([
                f"{b_url}/openapi/v1/{omadac_id}/system/setting/ssl-key",
                f"{b_url}/{omadac_id}/openapi/v1/system/setting/ssl-key"
            ])

    # Method 1: Dual-step upload (Certificate to /certificate AND SSL Key to /ssl-key) for PEM mode
    cert_uploaded = False
    key_uploaded = False

    for c_url in cert_urls:
        for headers in headers_list:
            try:
                logger.info(f"Uploading SSL Certificate (fullchain.pem) to {c_url}...")
                files = {"file": ("fullchain.pem", cert_bytes, "application/x-pem-file")}
                params = {"cerName": "fullchain.pem"}
                data = {"cerName": "fullchain.pem"}
                res = session.post(c_url, headers=headers, params=params, data=data, files=files, timeout=30)
                if res.status_code == 200:
                    res_json = res.json()
                    if res_json.get("errorCode") == 0:
                        logger.info("SSL Certificate successfully uploaded via OpenAPI!")
                        cert_uploaded = True
                        break
                    else:
                        logger.debug(f"OpenAPI cert response at {c_url}: {res_json.get('msg')} (code {res_json.get('errorCode')})")
            except Exception as exc:
                logger.debug(f"Exception during OpenAPI cert upload: {exc}")
        if cert_uploaded:
            break

    for k_url in key_urls:
        for headers in headers_list:
            try:
                logger.info(f"Uploading SSL Key (privkey.pem) to {k_url}...")
                files = {"file": ("privkey.pem", key_bytes, "application/x-pem-file")}
                params = {"keyName": "privkey.pem"}
                data = {"keyName": "privkey.pem"}
                res = session.post(k_url, headers=headers, params=params, data=data, files=files, timeout=30)
                if res.status_code == 200:
                    res_json = res.json()
                    if res_json.get("errorCode") == 0:
                        logger.info("SSL Key successfully uploaded via OpenAPI!")
                        key_uploaded = True
                        break
                    else:
                        logger.debug(f"OpenAPI key response at {k_url}: {res_json.get('msg')} (code {res_json.get('errorCode')})")
            except Exception as exc:
                logger.debug(f"Exception during OpenAPI key upload: {exc}")
        if key_uploaded:
            break

    if cert_uploaded and key_uploaded:
        time.sleep(1)
        updated_cert = get_openapi_certificate_info(session, base_urls, token, omadac_id)
        if updated_cert is not None:
            logger.info(f"Updated Omada certificate status after upload: {updated_cert}")
        return True

    # Method 2: Single bundle upload (.pem combined or .pfx)
    bundle_variants = [
        ("omada_cert.pem", combined_pem_bytes, "application/x-pem-file"),
        ("omada_cert.pfx", pfx_bytes, "application/x-pkcs12")
    ]
    for c_url in cert_urls:
        for fname, fbytes, mtype in bundle_variants:
            if not fbytes:
                continue
            for headers in headers_list:
                try:
                    logger.info(f"Uploading certificate bundle ({fname}) to {c_url}...")
                    files = {"file": (fname, fbytes, mtype)}
                    params = {"cerName": fname}
                    data = {"cerName": fname}
                    res = session.post(c_url, headers=headers, params=params, data=data, files=files, timeout=30)
                    if res.status_code == 200:
                        res_json = res.json()
                        if res_json.get("errorCode") == 0:
                            logger.info(f"Certificate bundle '{fname}' uploaded via OpenAPI!")
                            time.sleep(1)
                            updated_cert = get_openapi_certificate_info(session, base_urls, token, omadac_id)
                            if updated_cert is not None:
                                logger.info(f"Updated Omada certificate status: {updated_cert}")
                            return True
                except Exception as exc:
                    logger.debug(f"Exception during OpenAPI bundle upload: {exc}")

    return False


def upload_ssl_certificate(session, base_url, token, omadac_id, auth_type, cert_path, key_path):
    """Upload SSL Certificate and Private Key to Omada Controller."""
    if not os.path.exists(cert_path):
        logger.error(f"Certificate file not found: {cert_path}")
        return False
    if not os.path.exists(key_path):
        logger.error(f"Key file not found: {key_path}")
        return False

    base_urls = []
    if ":443" in base_url:
        base_urls = [base_url, base_url.replace(":443", ":8043")]
    elif ":8043" in base_url:
        base_urls = [base_url.replace(":8043", ":443"), base_url, base_url.replace(":8043", "")]
    else:
        base_urls = [f"{base_url}:443", f"{base_url}:8043", base_url]

    with open(cert_path, "rb") as cf:
        cert_bytes = cf.read()
    with open(key_path, "rb") as kf:
        key_bytes = kf.read()

    # Create combined PEM bundle (fullchain + private key)
    combined_pem_bytes = cert_bytes.rstrip() + b"\n" + key_bytes.lstrip()

    # Create PKCS#12 (.pfx) bundle without password
    pfx_bytes = None
    try:
        import subprocess
        pfx_proc = subprocess.run(
            ["openssl", "pkcs12", "-export", "-in", cert_path, "-inkey", key_path, "-passout", "pass:"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        pfx_bytes = pfx_proc.stdout
    except Exception as e:
        logger.debug(f"Could not generate PKCS12 pfx bundle: {e}")

    if auth_type == "openapi":
        if upload_openapi_cert_and_key(session, base_urls, token, omadac_id, cert_bytes, key_bytes, combined_pem_bytes, pfx_bytes):
            return True
        logger.warning("Omada OpenAPI certificate endpoints could not complete upload. Checking fallback routes...")

    # Web API session endpoints and fallback
    headers_list = [{"Csrf-Token": token}] if auth_type != "session" else [
        {"Csrf-Token": token},
        {"Csrf-Token": token, "Authorization": f"Bearer {token}"}
    ]

    candidate_upload_urls = []
    for b_url in base_urls:
        if omadac_id:
            candidate_upload_urls.extend([
                f"{b_url}/{omadac_id}/api/v2/system/setting/certificate",
                f"{b_url}/{omadac_id}/api/v2/system/setting/ssl",
                f"{b_url}/{omadac_id}/api/v2/maintenance/ssl",
                f"{b_url}/{omadac_id}/api/v2/system/ssl",
                f"{b_url}/{omadac_id}/api/v2/maintenance/customcert",
                f"{b_url}/{omadac_id}/api/v2/ssl/customcert",
                f"{b_url}/api/v2/system/setting/certificate",
                f"{b_url}/api/v2/maintenance/ssl",
                f"{b_url}/api/v2/system/ssl"
            ])
        else:
            candidate_upload_urls.extend([
                f"{b_url}/api/v2/system/setting/certificate",
                f"{b_url}/api/v2/system/setting/ssl",
                f"{b_url}/api/v2/maintenance/ssl",
                f"{b_url}/api/v2/system/ssl",
                f"{b_url}/api/v2/maintenance/customcert",
                f"{b_url}/api/v2/ssl/customcert"
            ])

    # De-duplicate while preserving order
    seen_urls = set()
    upload_urls = []
    for u in candidate_upload_urls:
        if u not in seen_urls:
            seen_urls.add(u)
            upload_urls.append(u)

    # Form/Multipart variations corresponding to the Web UI PEM Import dialog:
    # 1) Standard Omada PEM (separate certFile and keyFile with format indicators)
    # 2) Standard Web UI fields (certificate + key or file + key)
    multipart_combinations = [
        # (files_dict, data_dict)
        (
            {
                "certFile": ("cert.pem", cert_bytes, "application/x-pem-file"),
                "keyFile": ("key.pem", key_bytes, "application/x-pem-file")
            },
            {"fileFormat": "PEM", "cerType": "PEM", "type": 1}
        ),
        (
            {
                "certFile": ("fullchain.pem", cert_bytes, "application/x-pem-file"),
                "keyFile": ("privkey.pem", key_bytes, "application/x-pem-file")
            },
            {"type": 1}
        ),
        (
            {
                "certificate": ("cert.pem", cert_bytes, "application/x-pem-file"),
                "key": ("key.pem", key_bytes, "application/x-pem-file")
            },
            {"fileFormat": "PEM"}
        ),
        (
            {
                "file": ("cert.pem", cert_bytes, "application/x-pem-file"),
                "key": ("key.pem", key_bytes, "application/x-pem-file")
            },
            {"cerType": "PEM", "cerName": "cert.pem"}
        ),
        (
            {
                "file": ("omada_cert.pem", combined_pem_bytes, "application/x-pem-file")
            },
            {"cerName": "omada_cert.pem", "cerType": "PEM"}
        )
    ]

    for url in upload_urls:
        for headers in headers_list:
            for files, data in multipart_combinations:
                try:
                    logger.info(f"Uploading PEM certificate and key to {url}...")
                    res = session.post(url, headers=headers, data=data, files=files, timeout=30)

                    if res.status_code == 200:
                        try:
                            res_json = res.json()
                            if res_json.get("errorCode") == 0:
                                logger.info("SSL Certificate successfully uploaded and installed on Omada Controller!")
                                return True
                            else:
                                logger.warning(f"Omada response at {url}: {res_json.get('msg')} (code {res_json.get('errorCode')})")
                        except Exception:
                            logger.debug(f"Received non-JSON response from {url}: {res.text[:100]}")
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

    parsed_url = urlparse(url)
    host = parsed_url.hostname or url.replace("https://", "").replace("http://", "").split(":")[0]
    port = parsed_url.port or (8043 if ":8043" in url else (443 if ":443" in url else 8043))

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
            logger.info(f"Omada Controller Live TLS Certificate (port {p}): Subject={live_cert.get('subject')}, Expires={live_cert.get('notafter')}")
            break

    # Build base URLs for OpenAPI
    base_urls = []
    if ":443" in url:
        base_urls = [url, url.replace(":443", ":8043")]
    elif ":8043" in url:
        base_urls = [url.replace(":8043", ":443"), url, url.replace(":8043", "")]
    else:
        base_urls = [f"{url}:443", f"{url}:8043", url]

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

    # Check if Omada certificate is already active, valid, and enabled
    if auth_type == "openapi":
        existing_cert = get_openapi_certificate_info(session, base_urls, token, omadac_id)
        if existing_cert is not None:
            logger.info(f"Omada Controller Setting Status: {existing_cert}")
            if live_cert and local_fp and live_cert.get("sha256 fingerprint") == local_fp and existing_cert.get("enable") is True:
                logger.info("Omada Controller is already active with the valid, matching certificate. No update required.")
                logout_omada(session, url, token, omadac_id, auth_type)
                sys.exit(0)
    else:
        if live_cert and local_fp and live_cert.get("sha256 fingerprint") == local_fp:
            logger.info("Omada Controller is already active with the valid, matching certificate. No update required.")
            logout_omada(session, url, token, omadac_id, auth_type)
            sys.exit(0)

    logger.info("Omada Controller certificate needs updating (expired, disabled, or does not match). Proceeding with upload...")

    success = False
    if auth_type == "openapi":
        success = upload_ssl_certificate(session, url, token, omadac_id, auth_type, cert_path, key_path)
        if not success:
            logger.warning("Omada OpenAPI does not support SSL certificate uploads (TP-Link OpenAPI restricts controller SSL management to the Web UI).")
            if has_userpass:
                logger.info("Falling back to Omada Web Management API (username & password) to install certificate...")
                session_web = requests.Session()
                session_web.verify = verify_ssl
                web_token, web_omadac_id, web_auth_type = authenticate_user_pass(session_web, url, username, password, omadac_id)
                if web_token:
                    success = upload_ssl_certificate(session_web, url, web_token, web_omadac_id, web_auth_type, cert_path, key_path)
                    logout_omada(session_web, url, web_token, web_omadac_id, web_auth_type)
            else:
                logger.error("Omada requires administrator 'username' and 'password' in the add-on configuration to install SSL certificates via the Web API.")
    else:
        success = upload_ssl_certificate(session, url, token, omadac_id, auth_type, cert_path, key_path)

    logout_omada(session, url, token, omadac_id, auth_type)

    if not success:
        sys.exit(1)

    logger.info("Omada SSL deployment completed successfully.")


if __name__ == "__main__":
    main()
