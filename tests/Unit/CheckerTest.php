<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Event\SecurityFindingsFoundEvent;
use Ruvelo\SecurityAlerts\Tests\Support\Fakes;
use Ruvelo\SecurityAlerts\Tests\Support\Harness;

class CheckerTest extends TestCase
{
    private function withFlaws(Harness $h): void
    {
        $h->advisories->byPackage['shopware/core'] = [Fakes::advisory('shopware/core', 'PKSA-1', Severity::Critical, 'CVE-2026-1111')];
        $h->advisories->byPackage['acme/shopware-widgets'] = [Fakes::advisory('acme/shopware-widgets', 'PKSA-2', Severity::Low)];
        $h->kev->exploited = ['CVE-2026-1111'];
    }

    public function testItReadsShopwareCoreAndComposerPluginsFromTheLockfile(): void
    {
        $h = new Harness();
        $outcome = $h->checker->scan();

        $this->assertSame(['composer' => 4], $outcome->report->packages);
        $this->assertTrue($outcome->report->isComplete());
    }

    public function testZipPluginsAreListedAsNotCheckedAndDoNotMakeTheReportIncomplete(): void
    {
        $h = new Harness();
        $outcome = $h->checker->scan();

        $this->assertTrue($outcome->report->isComplete());
        $this->assertSame([], $outcome->report->problems);
        $this->assertCount(1, $outcome->notChecked);
        $this->assertSame('Acme_Zip', $outcome->notChecked[0]->name);
        $this->assertSame('not checked (not installed with Composer)', $outcome->toArray()['not_checked'][0]['reason']);
        $this->assertSame('1.2.3', $outcome->toArray()['not_checked'][0]['version']);
    }

    public function testExploitedComesFirstAndTheStoreRemembersIt(): void
    {
        $h = new Harness();
        $this->withFlaws($h);

        $outcome = $h->checker->run();

        $this->assertSame('shopware/core', $outcome->report->findings[0]->package);
        $this->assertTrue($outcome->report->findings[0]->isExploited());
        $this->assertCount(2, $h->store->rows);
        $this->assertSame('shopware/core', $h->store->all()[0]->package);
        $this->assertNotNull($h->recorded);
    }

    public function testADryRunStoresNothingSendsNothingAndDispatchesNothing(): void
    {
        $h = new Harness();
        $this->withFlaws($h);
        $dispatched = 0;
        $h->events->addListener(SecurityFindingsFoundEvent::NAME, function () use (&$dispatched): void {
            ++$dispatched;
        });

        $outcome = $h->checker->scan();

        $this->assertCount(2, $outcome->report->findings);
        $this->assertSame([], $h->store->rows);
        $this->assertSame([], $h->mail->sent);
        $this->assertSame(0, $dispatched);
        $this->assertNull($h->recorded);
    }

    public function testItDispatchesTheEventWithTheChangesOnlyWhenThereAreFindings(): void
    {
        $h = new Harness();
        /** @var \ArrayObject<int, SecurityFindingsFoundEvent> $events */
        $events = new \ArrayObject();
        $h->events->addListener(SecurityFindingsFoundEvent::NAME, function (SecurityFindingsFoundEvent $e) use ($events): void {
            $events[] = $e;
        });

        $h->checker->run();
        $this->assertCount(0, $events);

        $this->withFlaws($h);
        $h->checker->run();
        $this->assertCount(1, $events);
        $this->assertCount(2, $this->event($events, 0)->changes->new);
        $this->assertCount(1, $this->event($events, 0)->changes->exploited);

        $h->checker->run();
        $this->assertCount(2, $events);
        $this->assertSame([], $this->event($events, 1)->changes->new);
    }

    public function testOnlyNewFindingsAreEmailedAndTheSecondRunIsQuiet(): void
    {
        $h = new Harness();
        $this->withFlaws($h);

        $first = $h->checker->run();
        // The low one is below the default minimum (medium): handled, not emailed.
        $this->assertSame(1, $first->notified);
        $this->assertCount(1, $h->mail->sent);
        $this->assertSame([], $h->store->pending());

        $second = $h->checker->run();
        $this->assertSame(0, $second->notified);
        $this->assertCount(1, $h->mail->sent);
    }

    public function testAFindingThatBecomesExploitedIsEmailedAgain(): void
    {
        $h = new Harness();
        $h->advisories->byPackage['shopware/core'] = [Fakes::advisory('shopware/core', 'PKSA-1', Severity::High, 'CVE-2026-1111')];
        $h->checker->run();
        $this->assertCount(1, $h->mail->sent);

        $h->kev->exploited = ['CVE-2026-1111'];
        $outcome = $h->checker->run();

        $this->assertSame(1, $outcome->notified);
        $this->assertCount(2, $h->mail->sent);
        $this->assertStringContainsString('Exploited', $h->mail->sent[1]['data']['subject']);
    }

    public function testExploitedStaysExploitedWhenCisaCannotBeReadButAFixedFindingIsResolved(): void
    {
        $h = new Harness();
        $this->withFlaws($h);
        $h->checker->run();

        // The package is updated: the advisory no longer applies. The other one stays.
        unset($h->advisories->byPackage['shopware/core']);
        $h->checker->run();

        $this->assertSame(['composer:acme/shopware-widgets:PKSA-2'], array_keys($h->store->rows));
    }

    public function testAnIncompleteCheckNeverResolvesAnything(): void
    {
        $h = new Harness();
        $this->withFlaws($h);
        $h->checker->run();

        $h->advisories->down = true;
        $outcome = $h->checker->run();

        $this->assertFalse($outcome->report->isComplete());
        $this->assertCount(2, $h->store->rows);
    }

    /**
     * @param \ArrayObject<int, SecurityFindingsFoundEvent> $events
     */
    private function event(\ArrayObject $events, int $index): SecurityFindingsFoundEvent
    {
        return $events->offsetGet($index) ?? throw new \LogicException('no such event');
    }
}
