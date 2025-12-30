# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/vakamo-labs/middle-rs/compare/v0.3.1...v0.4.0) - 2025-12-30

- *(deps)* Update to tonic 14 ([#22](https://github.com/vakamo-labs/middle-rs/pull/22))
- Update Readme examples
- *(deps)* Update typed-builder requirement from 0.20 to 0.21 ([#10](https://github.com/vakamo-labs/middle-rs/pull/10))

## [0.3.0](https://github.com/vakamo-labs/middle-rs/compare/v0.2.1...v0.3.0) - 2025-02-26

### Added

- Credential refresh should stop only when RefreshTask is dropped (#8)

## [0.2.1](https://github.com/vakamo-labs/middle-rs/compare/v0.2.0...v0.2.1) - 2025-02-26

### Fixed

- Missing Bearer prefix for Client-Credential flows (#5)

## [0.2.0](https://github.com/vakamo-labs/middle-rs/compare/v0.1.0...v0.2.0) - 2025-02-20

### Fixed

- [**breaking**] Rename `simple_builder` to `basic_builder` for `oauth2` consistency (#4)

### Other

- No docs duplication
- *(deps)* Update veil requirement from 0.1 to 0.2 (#2)
- *(ci)* Fix CI (#3)
