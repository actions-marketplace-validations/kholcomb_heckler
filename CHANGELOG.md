# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-23

### Added

- Detect UTF-16/32 encoded files to prevent encoding evasion
- Prefer wheel downloads in `--vet` to avoid setup.py code execution
- Scan well-known extensionless files (Dockerfile, Makefile, etc.) by default
- Add file extensions for 30+ additional languages
- Expand dependency scan extensions to cover multi-language ecosystems

### Changed

- Replace npm/pip subprocess calls with direct registry API fetches

### Fixed

- Fix repository URLs from heckler/heckler to kholcomb/heckler
- Fix target/build/dist skip dirs conflicting with `--scan-deps`
- Fix suppression directive bypass in `--vet` mode

### Security

- Harden scanner against threat-model bypass techniques
- Harden suppression directives against bypass attacks

## [0.2.0] - 2026-03-23

### Added

- Integration tests and updated README

### Fixed

- Fix `--vet` CLI flag broken by argparse mutually exclusive group
- Fix correctness issues across scanner, vet, lockfile, and formatters

### Security

- Fix critical security issues in archive extraction and scanner
- Fix shell injection in action.yml and harden CI workflows

## [0.1.0] - 2026-03-23

Initial release.

[0.3.0]: https://github.com/kholcomb/heckler/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kholcomb/heckler/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kholcomb/heckler/releases/tag/v0.1.0
