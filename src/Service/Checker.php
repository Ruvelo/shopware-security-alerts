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
        private readonly Inventory $inventory,
        private readonly Notifier $notifier,
        private readonly CheckState $state,
        private readonly EventDispatcherInterface $events,
        private readonly Reconciler $reconciler = new Reconciler(),
    ) {
    }

    /** Looks only: stores nothing, sends nothing, dispatches nothing. */
    public function scan(bool $fresh = false): CheckOutcome
    {
        return new CheckOutcome($this->scanners->scanner()->scan($fresh), $this->inventory->notInstalledWithComposer()->packages());
    }

    public function run(bool $fresh = false): CheckOutcome
    {
        $scanned = $this->scan($fresh);
        $report = $scanned->report;

        $changes = $this->reconciler->reconcile($this->store->known(), $report);
        $this->store->save($report->findings, $changes->resolved);
        $this->state->record($report);

        if ($report->findings !== []) {
            $this->events->dispatch(new SecurityFindingsFoundEvent($report, $changes), SecurityFindingsFoundEvent::NAME);
        }

        return new CheckOutcome($report, $scanned->notChecked, $changes, $this->notifier->notifyPending());
    }
}
