<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Severity;

/**
 * A finding as the store remembers it: what the admin lists and the email describes.
 */
final readonly class StoredFinding
{
    public function __construct(
        public string $key,
        public string $package,
        public string $installed,
        public string $advisoryId,
        public string $title,
        public Severity $severity,
        public ?string $cve = null,
        public ?string $link = null,
        public ?string $fixedIn = null,
        public bool $exploited = false,
        public ?string $kevAdded = null,
        public ?string $kevDue = null,
        public bool $ransomware = false,
        public bool $isDev = false,
        public bool $notified = false,
        public bool $notifiedExploited = false,
    ) {
    }

    /** Never told about yet, or told about before it was exploited. */
    public function isPending(): bool
    {
        return ! $this->notified || ($this->exploited && ! $this->notifiedExploited);
    }

    /** Worst first: exploited, then severity, then the most recently exploited, then the name. */
    public static function compare(self $a, self $b): int
    {
        return [$b->exploited, $b->severity->rank(), $b->kevAdded ?? '', $a->package, $a->advisoryId]
            <=> [$a->exploited, $a->severity->rank(), $a->kevAdded ?? '', $b->package, $b->advisoryId];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'key' => $this->key,
            'package' => $this->package,
            'installed' => $this->installed,
            'advisory_id' => $this->advisoryId,
            'title' => $this->title,
            'severity' => $this->severity->value,
            'severity_label' => $this->severity->label(),
            'cve' => $this->cve,
            'link' => $this->link,
            'fixed_in' => $this->fixedIn,
            'exploited' => $this->exploited,
            'kev_added' => $this->kevAdded,
            'kev_due' => $this->kevDue,
            'ransomware' => $this->ransomware,
            'dev' => $this->isDev,
        ];
    }
}
