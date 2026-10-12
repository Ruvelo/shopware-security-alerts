<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Report;

interface CheckState
{
    public function record(Report $report): void;

    /**
     * @return array{checked_at: string|null, complete: bool, kev_checked: bool, packages: int, problems: list<string>}|null
     */
    public function last(): ?array;
}
