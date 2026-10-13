# 1.1.0 (2026-10-13)

- Advisories now come from Valtry's signed Advisory API first (package names only, never versions), with Packagist and CISA used automatically if Valtry cannot answer.
- New setting "Advisory source": Valtry first (default) or public sources only. `RUVELO_ADVISORIES_SOURCE=public` does the same from the server environment.
- The administration page, the command and the JSON say which source answered.
- Upgrading from 1.0 sends no new emails and raises no new alerts.

# 1.0.0 (2026-10-12)

- First release.
- Daily check of shopware/core and every plugin and app installed with Composer against Packagist's security advisories, with the CISA list of vulnerabilities exploited in the wild shown first.
- Plugins that are not installed with Composer are listed as not checked.
- An administration page under Settings, System, Security alerts with a "Check now" button, and ACL privileges for viewing and checking.
- Email alerts through Shopware's mail service, only for new findings and findings that become exploited.
- Console command `ruvelo:security-alerts:check` with `--json`, `--fail-on` and exit codes 0, 1 and 2.
