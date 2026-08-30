# Changelog

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
