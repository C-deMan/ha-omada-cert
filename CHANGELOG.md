# Changelog

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
