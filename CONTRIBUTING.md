# Contributing to Ruvelo Security Alerts for Shopware 6

Thanks for helping! Bug reports, false positives, docs fixes and features are all welcome.

## Before you start

- **A wrong or missing finding:** open an issue with the package, the installed version and the advisory id. Matching rules and advisory data live in [ruvelo/security-advisories](https://github.com/Ruvelo/security-advisories) and Packagist, so a fix there reaches every Ruvelo adapter. An advisory that is wrong at the source should be fixed in [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories) too.
- **Features:** open an issue first if it is more than a small change.
- **Security issues:** don't open an issue. See [SECURITY.md](https://github.com/Ruvelo/.github/blob/main/SECURITY.md).

## Setup

You need PHP 8.2+ and Composer. You do not need a Shopware install or a database: `shopware/core` is a dev dependency (it ships the classes the plugin extends) and the tests use fakes for everything else.

`ruvelo/security-advisories` is tagged on GitHub but not on Packagist yet, so add it as a VCS repository first. Do not commit this line; the published `composer.json` must not carry repositories.

```bash
git clone https://github.com/<you>/shopware-security-alerts && cd shopware-security-alerts
composer config repositories.ruvelo-core vcs https://github.com/Ruvelo/security-advisories
composer install
git checkout composer.json     # drop the local repository line again
composer check
```

`composer check` runs exactly what CI runs:

| Command | What it does |
|---|---|
| `composer test` | PHPUnit unit tests, no network |
| `composer lint` | Laravel Pint, PSR-12 |
| `composer analyse` | PHPStan level 8 |

The `install` job in CI is the only thing that runs the plugin inside Shopware (6.6 and 6.7, MySQL 8, Mailpit). It uses the real Packagist and CISA feeds. Its helpers are in `.github/ci/`. It also builds the administration on 6.7 and screenshots the page with Playwright.

## Making a change

1. Branch from `main`.
2. Write a test that fails without your change.
3. Keep the public surface stable: the command options and exit codes, config keys, ACL privileges, API routes, the event name and its data, and the table.
4. Run `composer check`.
5. Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).

## Administration

The administration source is in `src/Resources/app/administration/src` and follows Shopware's documented plugin pattern (module, component, snippets, ACL mapping). Built files are not committed. Keep it minimal, and keep every string in the snippets, in English and German.
