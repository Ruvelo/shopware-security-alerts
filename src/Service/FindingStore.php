<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Finding;

interface FindingStore
{
    /**
     * @return array<string, bool> Finding key => whether it was exploited when last seen
     */
    public function known(): array;

    /**
     * @return list<StoredFinding> Worst first
     */
    public function all(): array;

    /**
     * Remember these findings (an exploited one stays exploited) and forget the resolved keys.
     *
     * @param list<Finding> $findings
     * @param list<string> $resolved
     */
    public function save(array $findings, array $resolved): void;

    /**
     * @return list<StoredFinding> Those nobody has been told about yet
     */
    public function pending(): array;

    /**
     * @param list<StoredFinding> $findings
     */
    public function markNotified(array $findings): void;
}
