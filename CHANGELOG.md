# Changelog
All notable changes to this project goes here.

## [v0.0.3] - 13-11-2018
### Changed
- Switch to Go 1.11

### Added
- Support to ignore certain ldap search requests.
- Test case if BIND DN is empty. 
- Pprof endpoint and mem usage stats.
- Systemd unit file.
- This changelog.
- Vendor in dependencies

### Fixed
- Ensure connections to backend ldap service are closed (reduce leaking goroutines).
- Check context is valid when connecting to backend ldap service.
