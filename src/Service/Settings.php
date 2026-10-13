<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Severity;

interface Settings
{
    /** Whether email alerts are on. The check itself always runs. */
    public function emailEnabled(): bool;

    /** @return list<string> Valid addresses only */
    public function recipients(): array;

    public function minimumSeverity(): Severity;

    /** The shop's own sender address, when it has one. */
    public function senderAddress(): ?string;

    /** "valtry" (the default: Valtry first, the public feeds as fallback) or "public" (never contact Valtry). */
    public function advisorySource(): string;

    /** Whether packages-dev from composer.lock are checked. */
    public function includeDev(): bool;
}
