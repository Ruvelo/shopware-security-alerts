<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Report;

final readonly class CheckOutcome
{
    /**
     * @param list<InstalledPackage> $notChecked Plugins not installed with Composer
     * @param Changes|null $changes Null for a dry run
     * @param int $notified How many findings went into an email
     */
    public function __construct(
        public Report $report,
        public array $notChecked,
        public ?Changes $changes = null,
        public int $notified = 0,
    ) {
    }

    /**
     * The report as JSON-ready data, with what could not be checked.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->report->toArray() + ['not_checked' => array_map(static fn (InstalledPackage $p): array => [
            'name' => $p->name,
            'version' => $p->version,
            'reason' => 'not checked (not installed with Composer)',
        ], $this->notChecked)];
    }
}
