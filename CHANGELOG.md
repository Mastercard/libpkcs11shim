# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2022-04-08
### Added
- support for hiding PIN/passphrase information. Enabled by default, can be switched off with `PKCS11SHIM_REVEALPIN` env variable.

### Changed
- print `CK_UNAVAILABLE_INFORMATION` when ulValueLen equals to -1

### Fixed
- compilation under MacOS

## [1.5.0] - 2022-04-05
### Added
- the library supports now forking. Log files are reopen and thread maintained over forks.
- the default build is now with OpenSSL disabled.

### Changed
- clearer layout in log files.

## [1.4.0] - 2022-03-21
### Added
- when specifying `PKCS11SHIM_OUTPUT`, any occurence of `%p` will be replaced by the PID
- process id added to logs

## [1.3.1] - 2022-03-10
### Fixed
- library crash when the env variable `PKCS11SHIM_OUTPUT` is not specified (workaround for older versions is to always specify it)

## [1.3.0] - 2022-03-09
### Changed
- the library can be compiled without `OpenSSL` (fancy printing of certificate attributes is disabled)

## [1.2.0] - 2022-01-17
### Changed
- using relaxed memory model for atomic counter of operations, should be faster on relaxed architecture (ARM)
- using latest PKCS#11 published standard ( v3.01 )
- updated autotools suite (requires now 2.71 )

## [1.0.0] - 2021-01-29
### Added

- initial official release

