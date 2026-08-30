# Changelog

## [1.2.1] - 2026-08-31

### Fixed
- Fixed `json.decoder.JSONDecodeError` during `deploy_omada.py` invocation by removing accidental code duplication and adding safe fallback checking when reading `options.json`.

## [1.2.0] - 2026-08-31

### Added
- **Home Assistant Ingress Web Dashboard**: Added an interactive web UI panel to Home Assistant with real-time status of Let's Encrypt and Omada Controller certificates.
- **Interactive Action Buttons**:
  - **Check & Sync Certificate Now**: Triggers on-demand certificate verification and deployment.
  - **Reboot Omada Controller Now**: Sends an immediate reboot command via OpenAPI to apply newly imported certificates.
  - **Clear Log File**: Clears add-on activity logs with one click.
- **Omada Maintenance Window & Reboot Scheduling**:
  - Automatically schedules controller reboots after certificate renewal to apply changes without disrupting daytime network traffic.
  - Configurable `reboot_schedule_day` (e.g., `any`, `sunday`) and `reboot_schedule_time` (e.g., `03:00` or `immediate`).
- **Cleaned up Authentication**: Removed legacy username/password authentication options across all scripts and configuration schemas, streamlining to secure OpenAPI Application Client credentials (`client_id` and `client_secret`).

## [1.1.8] - 2026-08-31

### Added
- **Live Omada Certificate Expiration & Match Verification**:
  - Removed local hash caching check in `run.sh` that previously skipped `deploy_omada.py`.
  - Added live TLS certificate inspection on the Omada Controller (comparing SHA256 fingerprint, subject, and expiration against the local Let's Encrypt certificate).
  - Inspects Omada controller certificate status (`enable: True`/`False`) via OpenAPI.
  - Automatically detects if the certificate served by Omada is expired, disabled, or self-signed, and initiates upload accordingly.

## [1.1.7] - 2026-08-31

### Added
- **Separate SSL Key Upload for OpenAPI PEM Mode**: Added support for `POST /openapi/v1/{omadacId}/system/setting/ssl-key` (`keyName=privkey.pem`) alongside `POST /openapi/v1/{omadacId}/system/setting/certificate` (`cerName=fullchain.pem`). This matches Omada's OpenAPI PEM certificate specification where certificate and private key are uploaded via their dedicated endpoints.

## [1.1.6] - 2026-08-31

### Fixed
- Prioritized OpenAPI port 443 routes during discovery and authentication to eliminate probing delays on port 8043.
- Added automatic before-and-after certificate status verification to log the updated `cerType`, `enable`, and certificate name directly from Omada.

## [1.1.5] - 2026-08-31

### Added
- **Omada Web UI PEM Mode Support**: Implemented exact multipart form payloads matching the Omada Controller Web UI "HTTPS Certificate" import dialog (PEM format with separate `SSL Certificate` and `SSL Key`, without password requirement).
- Added support for `/api/v2/system/setting/certificate` and `/api/v2/system/setting/ssl` endpoints.

## [1.1.4] - 2026-08-31

### Added
- **Official Omada OpenAPI Certificate Endpoint Implementation**:
  - Added query and upload support for official TP-Link OpenAPI endpoint: `POST /openapi/v1/{omadacId}/system/setting/certificate` with `cerName` query/multipart parameter.
  - Automatically generates combined `.pem` (fullchain + private key) and PKCS#12 `.pfx` bundles to support all Omada certificate storage formats.
  - Added `GET /openapi/v1/{omadacId}/system/setting/certificate` pre-check to inspect the active controller certificate status.

## [1.1.3] - 2026-08-30

### Added
- **Version Display in Banners**: Included add-on version (`vX.Y.Z`) in the start, stop, and renewal cycle log banners.
- Added `/etc/addon_config.yaml` to container image for reliable local version inspection.

### Fixed
- **Explicit Web API Credentials Notice**: Added clear error logging explaining that Omada SDN OpenAPI does not support controller SSL certificate uploads (Error `-1600 Unsupported request path`), and that configuring the Omada administrator `username` and `password` is required to deploy certificates via the Web Management API.
- Expanded candidate Web API upload endpoints (`/api/v2/maintenance/customcert`, `/api/v2/ssl/customcert`, etc.) and multi-port support.

## [1.1.2] - 2026-08-30

### Added
- **Automatic Local Timezone Detection**: Container now automatically detects and adopts the local timezone from Home Assistant Supervisor (`http://supervisor/core/info` / `homeassistant_api: true`) or custom `timezone` configuration option, ensuring all logs match local system time instead of UTC.
- Added `tzdata` package to image build.

### Fixed
- **Omada SSL Certificate Upload Fallback**: Omada OpenAPI specification natively delegates controller-level SSL maintenance to session-based Web APIs. If the controller returns `-1600 Unsupported request path` during OpenAPI upload, the deployment seamlessly falls back to Web API session authentication (`/api/v2/login`) to complete the certificate installation.

## [1.1.1] - 2026-08-30

### Fixed
- Updated SSL certificate upload routes in `deploy_omada.py` to automatically include OpenAPI port 443 routes alongside port 8043 routes.
- Added candidate endpoint structures (`/{omadacId}/openapi/v1/...`, `/openapi/v1/{omadacId}/...`, `/openapi/v1/system/ssl`, etc.) to match TP-Link OpenAPI standards.

## [1.1.0] - 2026-08-30

### Fixed
- Added dual-port probing for OpenAPI: Omada Controller hosts OpenAPI on port `443` (as designated in *Interface Access Address*) while management UI is on `8043`. The add-on now automatically tests both ports.
- Enhanced detailed error logging with exact error messages and codes returned by Omada.

## [1.0.9] - 2026-08-30

### Fixed
- Fixed Omada OpenAPI authentication error handling and broadened endpoint matrix to cover both standalone and global controller setups.
- Added graceful fallback to username/password authentication if OpenAPI is not enabled in controller settings.
- Cleaned up noisy repetitive warnings during discovery attempts.

## [1.0.8] - 2026-08-30

### Fixed
- **Persistent Certificate Storage**: Moved Certbot configuration, certificates, and work directories to Home Assistant persistent storage (`/data/letsencrypt`, `/data/letsencrypt-work`, `/data/letsencrypt-log`).
- **Prevent Unnecessary Certificate Requests**: With `--keep-until-expiring`, `--expand`, and persistent `/data`, Certbot now reuses existing certificates and only renews them when within the 30-day expiration window or when domain names change.
- **Smart Omada Deployment**: Tracks hash of deployed certificate in `/data/last_deployed_cert_hash` to avoid uploading the same certificate repeatedly on restart/scheduled checks.

## [1.0.7] - 2026-08-30

### Fixed
- Updated Omada OpenAPI token authentication according to TP-Link Northbound API Specification Section 2.3.1 (Client Credentials Mode).
- Endpoint now explicitly targets `POST /openapi/authorize/token?grant_type=client_credentials` with payload `{"omadacId": "...", "client_id": "...", "client_secret": "..."}`.

## [1.0.6] - 2026-08-30

### Added
- Formatted timestamped logging (`YYYY-MM-DD HH:MM:SS [LEVEL]`) across all shell script outputs to match the Python script log format.
- Clear and structured START and STOP visual banners for the service startup, shutdown, and renewal cycles.
- Signal trapping (`SIGTERM`, `SIGINT`, `SIGHUP`) to ensure a clean STOP banner is printed when the add-on is stopped or restarted.

## [1.0.5] - 2026-08-30

### Fixed
- Fixed Omada OpenAPI error `-44116` ("Open API Authorized failed, please check whether the input parameters are legal") by adding support for HMAC-SHA256 timestamped signatures, `appKey`/`appSecret` pairings, and GET-based token authorization formats.

## [1.0.4] - 2026-08-30

### Added
- Multi-variant OpenAPI authentication payload formats (`appId`, `app_id`, `client_id`, `appSecret`, `secret`).
- Automatic binding of auto-discovered Omada Controller ID (`omadacId`).
- Detailed error reporting and logging for Omada API responses.

### Changed
- Removed required manual `omadac_id` field from configuration options since it is discovered automatically.

## [1.0.3] - 2026-08-30

### Fixed
- Fixed s6-overlay PID 1 permission issue by setting `init: false` in `config.yaml`.

## [1.0.2] - 2026-08-30

### Added
- Support for Omada OpenAPI Application Client authentication (Client ID & Client Secret).
- Option to save certificates into a custom `/ssl/` subdirectory (`ssl_subdir`, defaulting to `omada`) to prevent overwriting Home Assistant's default certificates.

## [1.0.1] - 2026-08-30

### Fixed
- Fixed base image resolution by using `ghcr.io/home-assistant/{arch}-base:latest`.
- Added missing Python and Certbot dependency packages.

## [1.0.0] - 2026-08-30

### Added
- Initial release of the Home Assistant Add-on.
- Support for Let's Encrypt certificates via Certbot and Cloudflare DNS-01 challenge.
- Multi-architecture support (`aarch64`, `amd64`, `armhf`, `armv7`, `i386`).
- Automatic deployment to TP-Link Omada Controller (v4 and v5).
- Automatic export to Home Assistant `/ssl` directory.
- Periodic renewal daemon.
