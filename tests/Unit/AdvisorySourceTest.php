<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAlerts\Console\CheckCommand;
use Ruvelo\SecurityAlerts\Service\HttpScannerProvider;
use Ruvelo\SecurityAlerts\Service\Inventory;
use Ruvelo\SecurityAlerts\Tests\Support\FakeNetwork;
use Ruvelo\SecurityAlerts\Tests\Support\FakeSettings;
use Ruvelo\SecurityAlerts\Tests\Support\Harness;
use Ruvelo\SecurityAlerts\Tests\Support\MemoryStore;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The scanner as the plugin builds it: Valtry first, the public feeds as the way out, and the
 * "Advisory source" setting. All answers are fake and signed with a key made for the test.
 */
class AdvisorySourceTest extends TestCase
{
    protected function setUp(): void
    {
        putenv(Scanner::ENV);
        unset($_SERVER[Scanner::ENV], $_ENV[Scanner::ENV]);
    }

    protected function tearDown(): void
    {
        putenv(Scanner::ENV);
    }

    public static function network(): FakeNetwork
    {
        return new FakeNetwork([
            ['package' => 'shopware/core', 'id' => 'PKSA-core-1', 'cve' => 'CVE-2026-1111', 'affected' => '>=6.6.0,<6.6.11', 'title' => 'Core flaw'],
            ['package' => 'acme/shopware-widgets', 'id' => 'PKSA-w-2', 'affected' => '<3.0.0', 'title' => 'Widget flaw', 'severity' => 'low'],
        ], ['CVE-2026-1111']);
    }

    public static function harness(FakeNetwork $net, string $source = 'valtry', ?MemoryStore $store = null): Harness
    {
        $settings = new FakeSettings(source: $source);
        $inventory = new class () implements Inventory {
            public function notInstalledWithComposer(): ExtensionList
            {
                return new ExtensionList([['name' => 'Acme_Zip', 'version' => '1.2.3']], Ecosystem::Extension);
            }
        };
        $provider = new HttpScannerProvider(__DIR__.'/../fixtures', $settings, new ArrayAdapter(), $inventory, $net, $net->keys);

        return new Harness($store, $settings, $provider);
    }

    public function testByDefaultValtryAnswersAndOnlyNamesAreSent(): void
    {
        $net = self::network();
        $report = self::harness($net)->checker->scan()->report;

        $this->assertSame('valtry', $report->source);
        $this->assertCount(2, $report->findings);
        $this->assertTrue($report->findings[0]->isExploited());
        $this->assertTrue($report->isComplete());
        $this->assertSame(0, $net->sentTo('packagist.org'));
        $this->assertSame([], $net->stray);

        $sent = json_encode($net->valtryBodies, JSON_UNESCAPED_SLASHES);
        $this->assertStringContainsString('shopware/core', (string) $sent);
        $this->assertStringNotContainsString('6.6.10', (string) $sent, 'versions never leave the server');
        $this->assertStringNotContainsString('Acme_Zip', (string) $sent);
    }

    public function testThePublicSettingNeverContactsValtry(): void
    {
        $net = self::network();
        $report = self::harness($net, 'public')->checker->scan()->report;

        $this->assertSame('public', $report->source);
        $this->assertCount(2, $report->findings);
        $this->assertSame(0, $net->sentTo('valtry'));
        $this->assertSame(1, $net->sentTo('packagist.org'));
    }

    public function testTheEnvironmentOptOutWinsOverTheSetting(): void
    {
        putenv(Scanner::ENV.'=public');
        $net = self::network();
        $report = self::harness($net, 'valtry')->checker->scan()->report;

        $this->assertSame('public', $report->source);
        $this->assertSame(0, $net->sentTo('valtry'));
    }

    public function testItFallsBackToThePublicFeedsWhenValtryIsDownOrNotTrusted(): void
    {
        $net = self::network();
        $net->valtryDown = true;
        $report = self::harness($net)->checker->scan()->report;
        $this->assertSame('public', $report->source);
        $this->assertCount(2, $report->findings);
        $this->assertTrue($report->isComplete());

        $other = self::network();
        $provider = new HttpScannerProvider(__DIR__.'/../fixtures', new FakeSettings(), new ArrayAdapter(), null, $other, ['test-1' => base64_encode(random_bytes(32))]);
        $report = $provider->scanner()->scan();
        $this->assertSame('public', $report->source, 'an answer signed with another key is not used');
        $this->assertCount(2, $report->findings);
    }

    public function testZipPluginsAreReportedAsUncheckedNotAsAProblem(): void
    {
        $report = self::harness(self::network())->checker->scan()->report;

        $this->assertTrue($report->isComplete());
        $this->assertSame(['Acme_Zip'], array_map(static fn ($u): string => $u->package->name, $report->unchecked));
    }

    public function testTheCommandSaysWhereTheAdvisoriesCameFrom(): void
    {
        $t = new CommandTester(new CheckCommand(self::harness(self::network())->checker));
        $t->execute(['--dry-run' => true]);
        $this->assertStringContainsString('Advisory source: Valtry', $t->getDisplay());

        $t = new CommandTester(new CheckCommand(self::harness(self::network(), 'public')->checker));
        $t->execute(['--dry-run' => true, '--json' => true]);
        $data = json_decode($t->getDisplay(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame('public', $data['source']);
        $this->assertSame('Acme_Zip', $data['not_checked'][0]['name']);
    }
}
