# Home Assistant Add-on: Omada & Cloudflare SSL Certificate Manager

Automatically issue and renew Let's Encrypt certificates using the Cloudflare DNS-01 challenge, then automatically deploy them to your **TP-Link Omada Controller** (OC200, OC300, or Software Controller) and Home Assistant's `/ssl` directory.

## Features

- 🔒 **Let's Encrypt via Cloudflare DNS-01**: Issue valid wildcard or multi-domain SSL certificates without opening ports on your router (no port 80/443 forwarding required).
- 🔄 **Automatic Renewal**: Continuously checks and automatically renews certificates before expiration.
- 🚀 **Omada Controller Integration**: Directly uploads and installs the new certificate and private key to TP-Link Omada Controller via its REST API (supports Omada v4 and v5).
- 📁 **Home Assistant `/ssl` Export**: Stores `fullchain.pem` and `privkey.pem` in `/ssl/` for other add-ons (like NGINX, Mosquitto, Home Assistant Core, etc.).

## Installation

1. In Home Assistant, navigate to **Settings** -> **Add-ons** -> **Add-on Store**.
2. Click the three dots (top-right) -> **Repositories**.
3. Add the repository URL:
   ```text
   https://github.com/C-deMan/ha-omada-cert
   ```
4. Find **Omada & Cloudflare SSL Certificate Manager** in the store and click **Install**.

## Configuration

Navigate to the add-on's **Configuration** tab:

```yaml
domains:
  - omada.yourdomain.com
cloudflare_api_token: YOUR_CLOUDFLARE_API_TOKEN
letsencrypt_email: admin@yourdomain.com
letsencrypt_staging: false
renew_interval_hours: 12
copy_to_ha_ssl: true
ssl_subdir: omada
omada:
  enabled: true
  url: "https://192.168.1.1:8043"
  username: "your_omada_admin_username"
  password: "your_omada_admin_password"
  client_id: "YOUR_OMADA_CLIENT_ID"
  client_secret: "YOUR_OMADA_CLIENT_SECRET"
  omadac_id: ""
  verify_ssl: false
```

### Configuration Options

| Option | Type | Required | Description |
|---|---|---|---|
| `domains` | list | **Yes** | List of domain names to include in the certificate (e.g. `omada.example.com`, `*.example.com`). |
| `cloudflare_api_token` | string | **Yes** | Cloudflare API Token with `Zone:DNS:Edit` permission. |
| `letsencrypt_email` | string | **Yes** | Email address for Let's Encrypt registration and expiry notifications. |
| `letsencrypt_staging` | boolean | No | Set to `true` to test certificate generation against Let's Encrypt staging servers without hitting rate limits. |
| `renew_interval_hours` | integer | No | Interval (in hours) between renewal checks (default: `12`). |
| `copy_to_ha_ssl` | boolean | No | Copies the certificate files to `/ssl/` on Home Assistant (default: `true`). |
| `ssl_subdir` | string | No | Subdirectory inside `/ssl/` to store the certificates to prevent overwriting Home Assistant's default certificates (default: `omada`). |
| `timezone` | string | No | Custom timezone (e.g., `Europe/Amsterdam`). If left blank, automatically detected from Home Assistant. |
| `omada.enabled` | boolean | **Yes** | Set to `true` to push certificates to Omada Controller automatically. |
| `omada.url` | string | Conditional | URL of your Omada Controller (e.g. `https://192.168.1.1:8043`). |
| `omada.username` | string | **Required for SSL upload** | Administrator username for the Omada Web Management interface. |
| `omada.password` | string | **Required for SSL upload** | Administrator password for the Omada Web Management interface. |
| `omada.client_id` | string | Optional | Omada OpenAPI Application Client ID (App ID). |
| `omada.client_secret` | string | Optional | Omada OpenAPI Application Client Secret. |
| `omada.omadac_id` | string | No | Controller ID (auto-detected if omitted). |
| `omada.verify_ssl` | boolean | No | Set to `false` if your Omada controller currently uses a self-signed cert (default: `false`). |

### Setting up Omada OpenAPI Application

1. In your Omada Controller web interface, go to **Global View** -> **Settings** -> **OpenAPI** (or **API**).
2. Enable OpenAPI.
3. Click **Add Application** / **Create Application**.
4. Set a name (e.g., `Home Assistant Cert Renewal`) and assign administrator permissions.
5. Copy the generated **Client ID** (App ID) and **Client Secret** into the add-on configuration.

### Creating the Cloudflare API Token

1. Log in to your [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) and go to **My Profile** -> **API Tokens**.
2. Click **Create Token**, then scroll to **Create Custom Token** -> click **Get started**.
3. **Token name**: Give it a name like `homeassistant omada`.
4. **Permissions**:
   - Permission 1: **`Zone`** -> **`DNS`** -> **`Edit`**
   - Click **`+ Add more`**
   - Permission 2: **`Zone`** -> **`Zone`** -> **`Read`**
5. **Zone Resources**:
   - **`Include`** -> **`Specific zone`** -> select your domain (e.g., `yourdomain.com`), or select **`All zones`**.
6. **Client IP Address Filtering** and **TTL**: Leave as default (blank).
7. Click **Continue to summary** -> **Create Token**.
8. Copy the generated token into the `cloudflare_api_token` field in the add-on configuration.
