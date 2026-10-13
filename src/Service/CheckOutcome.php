<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\UncheckedPackage;

final readonly class CheckOutcome
{
    public const NOT_CHECKED = 'not checked (not installed with Composer)';

    /**
     * @param Changes|null $changes Null for a dry run
     * @param int $notified How many findings went into an email
     */
    public function __construct(
        public Report $report,
        public ?Changes $changes = null,
        public int $notified = 0,
    ) {
    }

    /**
     * Plugins not installed with Composer: the report's unchecked packages.
     *
     * @return list<InstalledPackage>
     */
    public function notChecked(): array
    {
        return array_map(static fn (UncheckedPackage $u): InstalledPackage => $u->package, $this->report->unchecked);
    }

    /**
     * The report as JSON-ready data, with what could not be checked.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->report->toArray() + ['not_checked' => self::notCheckedRows($this->report)];
    }

    /**
     * @return list<array{name: string, version: string, reason: string}>
     */
    public static function notCheckedRows(Report $report): array
    {
        return array_map(static fn (UncheckedPackage $u): array => [
            'name' => $u->package->name,
            'version' => $u->package->version,
            'reason' => self::NOT_CHECKED,
        ], $report->unchecked);
    }
}
