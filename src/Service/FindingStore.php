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
     * @return array<string, array<mixed>> Finding key => the finding as last seen (Finding::toArray()), for the Reconciler
     */
    public function lastSeen(): array;

    /**
     * @return list<StoredFinding> Worst first
     */
    public function all(): array;

    /**
     * Remember these findings (an exploited one stays exploited) and forget the gone keys
     * (resolved, or collapsed into another entry).
     *
     * @param list<Finding> $findings
     * @param list<string> $resolved
     * @param array<string, string> $storedKeys Finding::key() => the key it is stored under (the one it was first stored with)
     * @param array<string, array<mixed>> $lastSeen Stored key => Finding::toArray(), as Reconciler::lastSeen() gave
     */
    public function save(array $findings, array $resolved, array $storedKeys = [], array $lastSeen = []): void;

    /**
     * @return list<StoredFinding> Those nobody has been told about yet
     */
    public function pending(): array;

    /**
     * @param list<StoredFinding> $findings
     */
    public function markNotified(array $findings): void;
}
