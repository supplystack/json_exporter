# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4] - 2022-12-14
### Added
- Capability to process endpoints returning flat text result instead of json
- Capability to configure system variables
- Capability to configure limited time results as transients
- Capability to cross-reference both system properties and transients in some settings (url, headers and 
  data payload)

### Changed
- Updated libraries versions to the latest versions at the time of the update
- Updated _README_ configuration example with settings matching both __system__ variables and __transients__
- Updated \_\_init\_\_ to move to version _0.2.4_ as it was still on the initial _1.0.0_, not one of the logged 
  versions :smiley:

## [0.2.3] - 2018-11-19
### Changed
- Require prometheus_client < 0.4.0 because of incompatible changes

## [0.2.2] - 2017-12-14
### Changed
- Use UntypedMetricFamily from upstream prometheus_client 0.1.0 library

## [0.2.1] - 2017-12-12
### Added
- Added default port and listen settings to help message

## [0.2.0] - 2017-12-08
### Added
- Added documentation to README.md

### Changed
- Rename exporter metrics

## [0.1.0] - 2017-12-08
### Added
- Initial version
