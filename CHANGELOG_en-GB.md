# 1.0.0 (2026-10-12)

- First release.
- Daily check of shopware/core and every plugin and app installed with Composer against Packagist's security advisories, with the CISA list of vulnerabilities exploited in the wild shown first.
- Plugins that are not installed with Composer are listed as not checked.
- An administration page under Settings, System, Security alerts with a "Check now" button, and ACL privileges for viewing and checking.
- Email alerts through Shopware's mail service, only for new findings and findings that become exploited.
- Console command `ruvelo:security-alerts:check` with `--json`, `--fail-on` and exit codes 0, 1 and 2.
