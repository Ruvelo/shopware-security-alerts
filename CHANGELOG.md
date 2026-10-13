# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-13

Requires `ruvelo/security-advisories` ^1.1. Backwards compatible: the command, its options and exit codes, the event, the administration API routes and the configuration keys keep working, and a shop upgrading from 1.0 gets no new alerts and no repeated emails.

### Added

- Valtry's signed Advisory API is the default advisory source, with Packagist and CISA used automatically whenever Valtry cannot answer (unreachable, slow, an error, an answer that does not verify, or stale data). Package names are sent to Valtry, never versions; answers are verified against keys pinned in the core library.
- Plugin setting "Advisory source": *Valtry first, public sources as fallback* (default) or *Public sources only*. `RUVELO_ADVISORIES_SOURCE=public` in the environment does the same and wins over the setting.
- The source that answered is shown in the administration page, in the command output and in the JSON (`source`, `sources`).
- `unchecked` and `notes` in the JSON, from the core's report. `not_checked` stays as it was.
- Migration `Migration1791846000AddLastSeenToFinding`: a `last_seen` column keeps each finding as last seen, so the same vulnerability named differently by another source (an advisory id versus a CVE, say) is recognised as the same finding.

### Changed

- Zip-installed plugins are now reported through the core's `Report::$unchecked` instead of a separate inventory lookup in the checker. The administration API's `not_checked` and `last_check` now come from the last stored check.
- Findings are stored under the key they were first stored with, and an entry is matched by its alternative keys (id, CVE, aliases). Switching the advisory source, or a different source winning, no longer re-sends an email or marks a finding resolved and new.
- The README and the setting's help text say plainly what is sent where.

### Internal

- `Checker`, `CheckOutcome`, `FindingStore`, `Settings` and `HttpScannerProvider` constructors and methods changed (the plugin's services, not its documented interface).

### Why 1.1.0 and not 2.0.0

Nothing in the documented public interface (command, JSON keys, event, routes, configuration) was removed or renamed, and the JSON only gained keys. The classes under `Service\` are wired by the plugin's own `services.xml` and are not documented API.

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
