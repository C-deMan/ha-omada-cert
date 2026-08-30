# Home Assistant Add-on: Omada & Cloudflare SSL Certificate Manager

[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-blue.svg)](https://www.home-assistant.io/addons/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Home Assistant Supervisor Add-on to automatically generate, renew, and deploy Let's Encrypt SSL certificates using the Cloudflare DNS-01 challenge. It can deploy certificates directly to your **TP-Link Omada Controller** (OC200, OC300, or Software Controller) and Home Assistant's `/ssl` storage.

---

## Highlights

- **DNS-01 Challenge**: No open ports (80/443) or port forwarding needed. Supports wildcard certificates (`*.yourdomain.com`).
- **Omada Controller Integration**: Pushes renewed certificates to your TP-Link Omada Controller via its API without manual intervention.
- **Home Assistant `/ssl` Support**: Copies the certificates to Home Assistant's shared `/ssl` folder for use by HA Core or other add-ons.
- **Automated Renewal**: Runs continuously in the background, checking and renewing certificates before expiration.

---

## Quick Start

### 1. Add Repository to Home Assistant

In Home Assistant:
1. Go to **Settings** -> **Add-ons** -> **Add-on Store**.
2. Click the three dots in the upper right -> **Repositories**.
3. Add this URL:
   ```text
   https://github.com/C-deMan/ha-omada-cert
   ```
4. Reload the store, select **Omada & Cloudflare SSL Certificate Manager**, and click **Install**.

### 2. Configure Add-on

Under the add-on's **Configuration** tab, specify your domains and Cloudflare token:

```yaml
domains:
  - "omada.yourdomain.com"
cloudflare_api_token: "your_cloudflare_dns_edit_api_token"
letsencrypt_email: "admin@yourdomain.com"
letsencrypt_staging: false
renew_interval_hours: 12
copy_to_ha_ssl: true
ssl_subdir: "omada"
omada:
  enabled: true
  url: "https://192.168.1.1:8043"
  username: "your_omada_admin_username"
  password: "your_omada_admin_password"
  client_id: "your_omada_client_id"
  client_secret: "your_omada_client_secret"
  omadac_id: ""
  verify_ssl: false
```

### 3. Start Add-on

Click **Start** and check the **Logs** tab to verify certificate issuance and deployment.

---

## Creating the Cloudflare API Token

To allow Let's Encrypt / Certbot to complete the DNS-01 challenge (creating the temporary `_acme-challenge` TXT records), create a custom token in Cloudflare:

1. Log in to your [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) and go to **My Profile** -> **API Tokens**.
2. Click **Create Token**, then scroll to the bottom and click **Create Custom Token** -> **Get started**.
3. **Token name**: Choose a descriptive name (e.g. `homeassistant omada`).
4. **Permissions**:
   - Add permission 1: **`Zone`** | **`DNS`** | **`Edit`** *(Required to add and remove DNS challenge TXT records)*
   - Add permission 2 (click *+ Add more*): **`Zone`** | **`Zone`** | **`Read`** *(Recommended to resolve Zone IDs)*
5. **Zone Resources**:
   - **`Include`** | **`Specific zone`** | Select your domain (e.g. `yourdomain.com`), or choose **`All zones`**.
6. **Client IP Address Filtering** & **TTL**: Leave blank (default).
7. Click **Continue to summary** -> **Create Token**.
8. Copy the generated token string into the add-on's `cloudflare_api_token` field.

---

## Documentation

For full configuration reference and details on setting up the Omada OpenAPI client, see [DOCS.md](DOCS.md).

## License

[MIT](LICENSE)
