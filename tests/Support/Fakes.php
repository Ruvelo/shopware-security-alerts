<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Support;

use Psr\Log\AbstractLogger;
use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\AdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\ExploitCatalogue;
use Ruvelo\SecurityAlerts\Service\FindingStore;
use Ruvelo\SecurityAlerts\Service\Settings;
use Ruvelo\SecurityAlerts\Service\StoredFinding;

final class Fakes
{
    public static function advisory(string $package, string $id, Severity $severity = Severity::High, ?string $cve = null): Advisory
    {
        return new Advisory($id, Ecosystem::Composer, $package, "Flaw $id in $package", "https://example.com/$id", $cve, $severity, null, null);
    }

    public static function stored(string $package, string $id, Severity $severity = Severity::High, bool $exploited = false, bool $notified = false, bool $notifiedExploited = false): StoredFinding
    {
        return new StoredFinding("composer:$package:$id", $package, '1.0.0', $id, "Flaw $id in $package", $severity, null, "https://example.com/$id", '1.0.1', $exploited, $exploited ? '2026-10-01' : null, null, false, false, $notified, $notifiedExploited);
    }

    /**
     * @param list<StoredFinding> $stored
     */
    public static function store(array $stored = []): MemoryStore
    {
        return new MemoryStore($stored);
    }
}

final class MemoryStore implements FindingStore
{
    /** @var array<string, StoredFinding> */
    public array $rows = [];
    public int $saves = 0;

    /**
     * @param list<StoredFinding> $stored
     */
    public function __construct(array $stored = [])
    {
        foreach ($stored as $s) {
            $this->rows[$s->key] = $s;
        }
    }

    public function known(): array
    {
        return array_map(static fn (StoredFinding $s): bool => $s->exploited, $this->rows);
    }

    public function all(): array
    {
        $all = array_values($this->rows);
        usort($all, StoredFinding::compare(...));

        return $all;
    }

    public function save(array $findings, array $resolved): void
    {
        ++$this->saves;
        foreach ($resolved as $key) {
            unset($this->rows[$key]);
        }
        foreach ($findings as $f) {
            /** @var Finding $f */
            $old = $this->rows[$f->key()] ?? null;
            $this->rows[$f->key()] = new StoredFinding(
                $f->key(),
                $f->package,
                $f->installed,
                $f->advisoryId,
                $f->title,
                $f->severity,
                $f->cve,
                $f->link,
                $f->fixedIn,
                $f->isExploited() || ($old !== null && $old->exploited),
                $f->exploited?->dateAdded->format('Y-m-d'),
                null,
                false,
                $f->isDev,
                $old !== null && $old->notified,
                $old !== null && $old->notifiedExploited,
            );
        }
    }

    public function pending(): array
    {
        return array_values(array_filter($this->all(), static fn (StoredFinding $s): bool => $s->isPending()));
    }

    public function markNotified(array $findings): void
    {
        foreach ($findings as $f) {
            $row = $this->rows[$f->key];
            $this->rows[$f->key] = new StoredFinding($row->key, $row->package, $row->installed, $row->advisoryId, $row->title, $row->severity, $row->cve, $row->link, $row->fixedIn, $row->exploited, $row->kevAdded, $row->kevDue, $row->ransomware, $row->isDev, true, $row->exploited);
        }
    }
}

final class FakeSettings implements Settings
{
    /**
     * @param list<string> $recipients
     */
    public function __construct(
        public bool $enabled = true,
        public array $recipients = ['owner@example.com'],
        public Severity $minimum = Severity::Medium,
        public bool $dev = false,
        public ?string $sender = 'shop@example.com',
    ) {
    }

    public function emailEnabled(): bool
    {
        return $this->enabled;
    }

    public function recipients(): array
    {
        return $this->recipients;
    }

    public function minimumSeverity(): Severity
    {
        return $this->minimum;
    }

    public function senderAddress(): ?string
    {
        return $this->sender;
    }

    public function includeDev(): bool
    {
        return $this->dev;
    }
}

final class FakeAdvisories implements AdvisorySource
{
    /** @var array<string, list<Advisory>> */
    public array $byPackage = [];
    public bool $down = false;

    public function supports(Ecosystem $ecosystem): bool
    {
        return $ecosystem === Ecosystem::Composer;
    }

    public function find(array $packages, bool $fresh = false): array
    {
        if ($this->down) {
            throw \Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable::because('Packagist', 'timeout');
        }
        $matches = [];
        foreach ($packages as $p) {
            foreach ($this->byPackage[$p->name] ?? [] as $advisory) {
                $matches[] = new AdvisoryMatch($p, $advisory, '9.9.9');
            }
        }

        return $matches;
    }
}

final class FakeKev implements ExploitCatalogue
{
    /** @var list<string> */
    public array $exploited = [];

    public function lookup(array $cves, bool $fresh = false): array
    {
        $out = [];
        foreach ($cves as $cve) {
            if (in_array($cve, $this->exploited, true)) {
                $out[strtoupper($cve)] = new KevEntry($cve, 'Exploited thing', new \DateTimeImmutable('2026-10-01'), new \DateTimeImmutable('2026-10-22'));
            }
        }

        return $out;
    }
}

final class MemoryLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $lines = [];

    public function log($level, string|\Stringable $message, array $context = []): void
    {
        $this->lines[] = (string) $message;
    }
}
