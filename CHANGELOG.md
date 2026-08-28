# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses `vMAJOR.MINOR.PATCH`
git tags for releases.

## [0.1.4] - 2026-08-28

### Changed
- Restart `gtmd` after HTTPD recovers when GTM is configured on the node.

### Removed
- Removed support for the `acme_profile` configuration option.
- Stopped overwriting `/config/big3d/client.crt`.

## [0.1.3] - 2026-04-20

### Added
- Documented Python runtime compatibility and release expectations in the README.

### Changed
- Added Python 3.9.25 compatibility by replacing Python 3.10-only type annotation syntax.
- Noted the Python 3.9.25+ runtime baseline in `requirements.txt`.

### Fixed
- Prevented startup failures on Python 3.9.x caused by `str | None` and built-in generic type syntax in annotations.

## [0.1.2] - 2026-04-03

### Changed
- Renamed `f5_deploy` to `f5_ltm` to make room for separate `f5_httpd` support.

