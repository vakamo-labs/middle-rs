# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/vakamo-labs/middle-rs/compare/v0.5.0...v0.6.0) - 2026-11-27

### Added

- danger_http_client and danger_allow_http on TokenEndpointBuilder ([#48](https://github.com/vakamo-labs/middle-rs/pull/48))
- token exchange (RFC 8693) with TokenEndpoint::exchange, one request per call ([#47](https://github.com/vakamo-labs/middle-rs/pull/47))
- [**breaking**] one `oauth` feature for requested tokens; `rustls` for TLS ([#45](https://github.com/vakamo-labs/middle-rs/pull/45))
- refresh a JWT whose exp had passed within 10 s; AccessToken::with_expires_at ([#44](https://github.com/vakamo-labs/middle-rs/pull/44))
- [**breaking**] tokens from a TokenSource of your own; one SourceError for both source traits ([#42](https://github.com/vakamo-labs/middle-rs/pull/42))
- [**breaking**] one Authorizer type; JWT bearer grant (RFC 7523, section 2.1) ([#41](https://github.com/vakamo-labs/middle-rs/pull/41))
- authenticate the client with a JWT assertion (RFC 7523, section 2.2) ([#39](https://github.com/vakamo-labs/middle-rs/pull/39))
- [**breaking**] pass the client authentication to the builder; append parameters; refuse http token URLs ([#37](https://github.com/vakamo-labs/middle-rs/pull/37))
- [**breaking**] keep tokens fresh with a token cache ([#36](https://github.com/vakamo-labs/middle-rs/pull/36))
- sign JWT assertions with the jwt feature ([#35](https://github.com/vakamo-labs/middle-rs/pull/35))
- [**breaking**] request tokens with our own token-endpoint client on reqwest 0.13 ([#34](https://github.com/vakamo-labs/middle-rs/pull/34))

### Fixed

- token URL audience without its query; exp minus iat is the assertion lifetime; open the assertion file without blocking ([#40](https://github.com/vakamo-labs/middle-rs/pull/40))
- send token requests to localhost and loopback addresses without a proxy ([#38](https://github.com/vakamo-labs/middle-rs/pull/38))

### Other

- drop the cache's readers-gone shutdown; hanging-refresh test on the paused clock; fix the root README ([#46](https://github.com/vakamo-labs/middle-rs/pull/46))
- one check for a token that can follow Bearer; build the header without an error path ([#43](https://github.com/vakamo-labs/middle-rs/pull/43))
- add a scriptable fake token endpoint and pin the token request on the wire ([#32](https://github.com/vakamo-labs/middle-rs/pull/32))

## [0.5.0](https://github.com/vakamo-labs/middle-rs/compare/v0.4.0...v0.5.0) - 2026-07-01

### Fixed

- *(client-credentials)* harden token refresh and cache tonic metadata ([#28](https://github.com/vakamo-labs/middle-rs/pull/28))

### Other

- *(authorizers)* extract shared bearer-header builder ([#30](https://github.com/vakamo-labs/middle-rs/pull/30))
- *(deps)* bump mockito dev-dependency floor to 1.7 ([#29](https://github.com/vakamo-labs/middle-rs/pull/29))
- *(deps)* Update veil requirement from 0.2 to 0.3 ([#26](https://github.com/vakamo-labs/middle-rs/pull/26))

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
