# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-12

First release.

### Added

- Daily scheduled task `ruvelo.security_alerts.check` that checks `shopware/core` and every plugin and app installed with Composer, from `composer.lock`, against Packagist's security advisories, matched locally.
- The CISA Known Exploited Vulnerabilities catalogue: findings whose CVE is listed are marked "Exploited, patch now" and sorted first.
- Plugins that are not installed with Composer (zips under `custom/plugins`) are listed with their name and version as "not checked (not installed with Composer)", in the administration, the command and the JSON.
- `bin/console ruvelo:security-alerts:check` with `--json`, `--fail-on`, `--dry-run` and `--fresh`. Exit codes 0, 1 (a finding matched `--fail-on`) and 2 (incomplete check or a bad option).
- A DAL entity and migration (`ruvelo_security_alerts_finding`), so only new findings, and findings that became exploited, are emailed.
- Email through Shopware's mail service to the configured addresses, with a minimum severity (exploited findings are always sent), exploited first.
- Plugin configuration: send email alerts, recipients, minimum severity, include development packages.
- An administration page at Settings, System, Security alerts (Shopware 6.6 and 6.7) with "Check now", and the ACL privileges `ruvelo_security_alerts.viewer` and `.editor`. English and German snippets.
- Administration API routes `GET /api/_action/ruvelo-security-alerts/findings` and `POST .../check`, guarded by ACL.
- The event `ruvelo.security_alerts.found` with the report and what changed.
- CI: Pint, PHPStan level 8, unit tests on PHP 8.2 to 8.4, and a real install on Shopware 6.6 and 6.7 against MySQL 8.
