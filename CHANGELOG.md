# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-23

Initial stable release and GitHub Actions Marketplace launch.

### Added

- Detect dangerous invisible Unicode characters (Glassworm, Trojan Source, zero-width, tag characters)
- GitHub Actions Marketplace release (`uses: kholcomb/heckler@v1`)
- GitHub Release creation and floating major version tag in release workflow
- Detect UTF-16/32 encoded files to prevent encoding evasion
- Prefer wheel downloads in `--vet` to avoid setup.py code execution
- Scan well-known extensionless files (Dockerfile, Makefile, etc.) by default
- Support for 60+ language file extensions
- Multi-ecosystem dependency scanning (npm, pip, Cargo, Go, Ruby, etc.)
- Output formats: text, JSON, SARIF (with GitHub Security tab upload)
- Pre-commit hook integration
- Integration tests and hardening test suite

### Security

- Harden scanner against threat-model bypass techniques
- Harden suppression directives against bypass attacks
- Harden archive extraction against path traversal
- Replace npm/pip subprocess calls with direct registry API fetches

[1.0.0]: https://github.com/kholcomb/heckler/releases/tag/v1.0.0
