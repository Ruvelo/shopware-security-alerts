<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Event;

use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Report;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched after every recorded check that has at least one finding.
 * $changes says which are new or newly exploited.
 */
class SecurityFindingsFoundEvent extends Event
{
    public const NAME = 'ruvelo.security_alerts.found';

    public function __construct(
        public readonly Report $report,
        public readonly Changes $changes,
    ) {
    }
}
