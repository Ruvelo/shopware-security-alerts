<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAlerts\Event\SecurityFindingsFoundEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * One check: scan, remember what changed, tell the people who asked to be told.
 */
class Checker
{
    public function __construct(
        private readonly ScannerProvider $scanners,
        private readonly FindingStore $store,
        private readonly Notifier $notifier,
        private readonly CheckState $state,
        private readonly EventDispatcherInterface $events,
        private readonly Reconciler $reconciler = new Reconciler(),
    ) {
    }

    /** Looks only: stores nothing, sends nothing, dispatches nothing. */
    public function scan(bool $fresh = false): CheckOutcome
    {
        return new CheckOutcome($this->scanners->scanner()->scan($fresh));
    }

    public function run(bool $fresh = false): CheckOutcome
    {
        $report = $this->scan($fresh)->report;

        // The store keeps each finding under the key it was first stored with, plus what it
        // looked like, so the same flaw named differently by another source is not news.
        $known = $this->store->known();
        $lastSeen = $this->store->lastSeen();
        $changes = $this->reconciler->reconcile($known, $report, $lastSeen);
        $next = $this->reconciler->next($known, $report, [], $lastSeen);
        $seen = $this->reconciler->lastSeen($lastSeen, $report, $next);

        $current = [];
        foreach ($report->findings as $finding) {
            $current[$finding->key()] = true;
        }
        $storedKeys = [];
        foreach (array_keys($next) as $key) {
            $findingKey = $seen[$key]['key'] ?? null;
            if (is_string($findingKey) && isset($current[$findingKey])) {
                $storedKeys[$findingKey] = $key;
            }
        }

        $this->store->save($report->findings, array_values(array_diff(array_keys($known), array_keys($next))), $storedKeys, $seen);
        $this->state->record($report);

        if ($report->findings !== []) {
            $this->events->dispatch(new SecurityFindingsFoundEvent($report, $changes), SecurityFindingsFoundEvent::NAME);
        }

        return new CheckOutcome($report, $changes, $this->notifier->notifyPending());
    }
}
