# Change Log
This file contains all the notable changes done to the Ballerina SOAP package through the releases.

## [2.4.0] - 2026-10-16

### Added
- [Add the `sendRobust` API to the SOAP 1.1 and SOAP 1.2 clients to support the robust in-only message exchange pattern, reporting SOAP faults and network errors](https://github.com/ballerina-platform/module-ballerina-soap/pull/175)
- [Add the `soap:SoapFaultError` and `soap:NetworkError` subtypes of `soap:Error`, with typed detail records](https://github.com/ballerina-platform/module-ballerina-soap/pull/175)

### Changed

- [[#9301] Regroup standard library packages under new Area categories](https://github.com/ballerina-platform/ballerina-library/issues/9301)

## [2.3.2] - 2026-10-08

### Changed
- [[#9132] Updated Keywords and Reformat README for Connector Store Discoverability](https://github.com/ballerina-platform/ballerina-library/issues/9132)
- Narrow the exceptions thrown and caught in the WS-Security implementation to specific checked exceptions
- Upgrade Gradle to 9.5.1 and the Ballerina Gradle plugin to 4.0.0

## [0.9.0] - 2023-11-03

### Changed
- [Make some of the Java classes proper utility classes](https://github.com/ballerina-platform/ballerina-standard-library/issues/5075)

## [0.8.0] - 2023-10-16

### Added
- [Introduce soap standard library module](https://github.com/ballerina-platform/ballerina-standard-library/issues/4500)
- [Introduce basic soap client](https://github.com/ballerina-platform/ballerina-standard-library/issues/4618)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
