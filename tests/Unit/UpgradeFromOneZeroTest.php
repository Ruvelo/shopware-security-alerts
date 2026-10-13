<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAlerts\Tests\Support\Fakes;
use Ruvelo\SecurityAlerts\Tests\Support\MemoryStore;

/**
 * A shop that ran 1.0 has findings stored with no copy of the finding and an email already sent for
 * each. The first check after the upgrade must recognise them, whichever source answers, and send nothing again.
 */
class UpgradeFromOneZeroTest extends TestCase
{
    protected function setUp(): void
    {
        putenv(Scanner::ENV);
    }

    /** The store as 1.0 left it: keyed package:advisory, everything notified, the core flaw already exploited. */
    private function oneZeroStore(): MemoryStore
    {
        $core = Fakes::stored('shopware/core', 'PKSA-core-1', exploited: true, notified: true, notifiedExploited: true);
        $core = new \Ruvelo\SecurityAlerts\Service\StoredFinding($core->key, $core->package, '6.6.10.0', $core->advisoryId, 'Core flaw', $core->severity, 'CVE-2026-1111', $core->link, null, true, '2026-10-01', '2026-10-22', false, false, true, true);

        return new MemoryStore([$core, Fakes::stored('acme/shopware-widgets', 'PKSA-w-2', \Ruvelo\SecurityAdvisories\Severity::Low, notified: true)]);
    }

    private function assertNothingNew(\Ruvelo\SecurityAlerts\Tests\Support\Harness $h, MemoryStore $store): void
    {
        $outcome = $h->checker->run(true);

        $this->assertTrue($outcome->report->isComplete());
        $this->assertCount(2, $outcome->report->findings);
        $this->assertNotNull($outcome->changes);
        $this->assertSame([], $outcome->changes->new);
        $this->assertSame([], $outcome->changes->exploited);
        $this->assertSame([], $outcome->changes->resolved);
        $this->assertSame(0, $outcome->notified);
        $this->assertSame([], $h->mail->sent);
        $this->assertSame([], $store->pending());
        $this->assertSame(['composer:acme/shopware-widgets:PKSA-w-2', 'composer:shopware/core:PKSA-core-1'], $this->sorted(array_keys($store->rows)));
    }

    /**
     * @param list<string> $keys
     * @return list<string>
     */
    private function sorted(array $keys): array
    {
        sort($keys);

        return $keys;
    }

    public function testStoredFindingsAreKnownToThePublicPath(): void
    {
        $store = $this->oneZeroStore();
        $this->assertNothingNew(AdvisorySourceTest::harness(AdvisorySourceTest::network(), 'public', $store), $store);
    }

    public function testStoredFindingsAreKnownToTheValtryPath(): void
    {
        $net = AdvisorySourceTest::network();
        $store = $this->oneZeroStore();
        $h = AdvisorySourceTest::harness($net, 'valtry', $store);

        $this->assertNothingNew($h, $store);
        $this->assertSame('valtry', $h->recorded?->source);
    }

    public function testAFlawValtryNamesDifferentlyIsRecognisedByItsCveAndKeepsItsStoredKey(): void
    {
        $net = AdvisorySourceTest::network();
        $net->advisories[0]['valtryId'] = 'GHSA-xxxx-yyyy-zzzz';
        $store = $this->oneZeroStore();
        $h = AdvisorySourceTest::harness($net, 'valtry', $store);

        $this->assertNothingNew($h, $store);
        $this->assertArrayHasKey('composer:shopware/core:PKSA-core-1', $store->rows);
        $this->assertSame('GHSA-xxxx-yyyy-zzzz', $store->rows['composer:shopware/core:PKSA-core-1']->advisoryId);

        // And a later check, now with the stored copy of the finding, is quiet as well.
        $again = $h->checker->run(true);
        $this->assertNotNull($again->changes);
        $this->assertSame([], $again->changes->new);
        $this->assertSame(0, $again->notified);
    }

    public function testSwitchingSourceBetweenChecksSendsNothing(): void
    {
        $net = AdvisorySourceTest::network();
        $net->advisories[0]['valtryId'] = 'GHSA-xxxx-yyyy-zzzz';
        $store = new MemoryStore();

        $first = AdvisorySourceTest::harness($net, 'public', $store);
        $first->checker->run(true);
        $this->assertCount(1, $first->mail->sent);

        foreach (['valtry', 'public', 'valtry'] as $source) {
            $h = AdvisorySourceTest::harness($net, $source, $store);
            $outcome = $h->checker->run(true);
            $this->assertNotNull($outcome->changes);
            $this->assertSame([], $outcome->changes->new, $source);
            $this->assertSame([], $outcome->changes->resolved, $source);
            $this->assertSame([], $h->mail->sent, $source);
        }
        $this->assertCount(2, $store->rows);
    }
}
