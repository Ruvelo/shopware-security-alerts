<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Tests\Support\Fakes;
use Ruvelo\SecurityAlerts\Service\StoredFinding;

class StoredFindingTest extends TestCase
{
    public function testSortsExploitedThenSeverity(): void
    {
        $list = [
            Fakes::stored('a/low', '1', Severity::Low),
            Fakes::stored('b/crit', '2', Severity::Critical),
            Fakes::stored('c/exploited', '3', Severity::Medium, exploited: true),
            Fakes::stored('d/high', '4', Severity::High),
        ];
        usort($list, StoredFinding::compare(...));

        $this->assertSame(['c/exploited', 'b/crit', 'd/high', 'a/low'], array_map(static fn (StoredFinding $f): string => $f->package, $list));
    }

    public function testPendingMeansNeverToldOrToldBeforeItWasExploited(): void
    {
        $this->assertTrue(Fakes::stored('a/b', '1')->isPending());
        $this->assertFalse(Fakes::stored('a/b', '1', notified: true)->isPending());
        $this->assertTrue(Fakes::stored('a/b', '1', exploited: true, notified: true)->isPending());
        $this->assertFalse(Fakes::stored('a/b', '1', exploited: true, notified: true, notifiedExploited: true)->isPending());
    }

    public function testToArrayCarriesTheLabelAndExploitedFlag(): void
    {
        $a = Fakes::stored('a/b', '1', Severity::NotRated, exploited: true)->toArray();
        $this->assertTrue($a['exploited']);
        $this->assertSame('Not rated', $a['severity_label']);
        $this->assertSame('2026-10-01', $a['kev_added']);
    }
}
