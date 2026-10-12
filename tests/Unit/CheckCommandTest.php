<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Console\CheckCommand;
use Ruvelo\SecurityAlerts\Tests\Support\Fakes;
use Ruvelo\SecurityAlerts\Tests\Support\Harness;
use Symfony\Component\Console\Tester\CommandTester;

class CheckCommandTest extends TestCase
{
    private function tester(Harness $h): CommandTester
    {
        return new CommandTester(new CheckCommand($h->checker));
    }

    private function flawed(): Harness
    {
        $h = new Harness();
        $h->advisories->byPackage['shopware/core'] = [Fakes::advisory('shopware/core', 'PKSA-1', Severity::High, 'CVE-2026-1111')];
        $h->kev->exploited = ['CVE-2026-1111'];

        return $h;
    }

    public function testTheCommandIsNamedAsDocumented(): void
    {
        $this->assertSame('ruvelo:security-alerts:check', (new CheckCommand((new Harness())->checker))->getName());
    }

    public function testACleanShopExitsZeroAndSaysSo(): void
    {
        $t = $this->tester(new Harness());

        $this->assertSame(0, $t->execute(['--fail-on' => 'any']));
        $this->assertStringContainsString('No known vulnerabilities in 4 Composer packages', $t->getDisplay());
        $this->assertStringContainsString('Not checked (not installed with Composer): 1 plugins', $t->getDisplay());
    }

    public function testFailOnMatchesGivesOneAndWithoutItFindingsAreZero(): void
    {
        $this->assertSame(1, $this->tester($this->flawed())->execute(['--fail-on' => 'exploited']));
        $this->assertSame(0, $this->tester($this->flawed())->execute([]));
        $h = new Harness();
        $h->advisories->byPackage['shopware/core'] = [Fakes::advisory('shopware/core', 'PKSA-1', Severity::Low)];
        $this->assertSame(0, $this->tester($h)->execute(['--fail-on' => 'high']));
    }

    public function testAnIncompleteCheckAndABadOptionExitTwo(): void
    {
        $h = new Harness();
        $h->advisories->down = true;
        $this->assertSame(2, $this->tester($h)->execute([]));
        $this->assertSame(2, $this->tester(new Harness())->execute(['--fail-on' => 'sometimes']));
    }

    public function testJsonIsValidAndListsWhatIsNotChecked(): void
    {
        $t = $this->tester($this->flawed());
        $t->execute(['--json' => true, '--dry-run' => true]);

        $data = json_decode($t->getDisplay(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertTrue($data['findings'][0]['exploited']);
        $this->assertSame('Acme_Zip', $data['not_checked'][0]['name']);
        $this->assertFalse($data['clean']);
    }

    public function testDryRunStoresAndSendsNothing(): void
    {
        $h = $this->flawed();
        $this->tester($h)->execute(['--dry-run' => true]);
        $this->assertSame([], $h->store->rows);
        $this->assertSame([], $h->mail->sent);

        $this->tester($h)->execute([]);
        $this->assertCount(1, $h->store->rows);
        $this->assertCount(1, $h->mail->sent);
    }
}
