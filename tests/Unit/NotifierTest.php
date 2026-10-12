<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Tests\Support\FakeSettings;
use Ruvelo\SecurityAlerts\Tests\Support\Fakes;
use Ruvelo\SecurityAlerts\Tests\Support\Harness;

class NotifierTest extends TestCase
{
    public function testExploitedAreAlwaysSentAndMinimumSeverityFiltersTheRest(): void
    {
        $store = Fakes::store([
            Fakes::stored('a/low', 'L', Severity::Low),
            Fakes::stored('a/exploited-low', 'E', Severity::Low, exploited: true),
            Fakes::stored('a/high', 'H', Severity::High),
        ]);
        $h = new Harness($store, new FakeSettings(minimum: Severity::High));

        $this->assertSame(2, $h->notifier()->notifyPending());

        $text = (string) $h->mail->sent[0]['templateData']['ruvelo']['text'];
        $this->assertStringContainsString('a/exploited-low', $text);
        $this->assertStringContainsString('a/high', $text);
        $this->assertStringNotContainsString('a/low', $text);
        $this->assertLessThan(strpos($text, 'a/high'), strpos($text, 'a/exploited-low'), 'exploited first');
        // The one below the minimum is handled, so it is not reconsidered tomorrow.
        $this->assertSame([], $store->pending());
    }

    public function testNothingIsMarkedWhenEmailIsOffOrThereAreNoRecipients(): void
    {
        foreach ([new FakeSettings(enabled: false), new FakeSettings(recipients: [])] as $settings) {
            $store = Fakes::store([Fakes::stored('a/b', 'X')]);
            $h = new Harness($store, $settings);

            $this->assertSame(0, $h->notifier()->notifyPending());
            $this->assertSame([], $h->mail->sent);
            $this->assertCount(1, $store->pending(), 'turning email on later still reports what is open');
        }
    }

    public function testAFailedSendLeavesFindingsPendingAndLogs(): void
    {
        $store = Fakes::store([Fakes::stored('a/b', 'X')]);
        $h = new Harness($store);
        $h->mail->fail = true;

        $this->assertSame(0, $h->notifier()->notifyPending());
        $this->assertCount(1, $store->pending());
        $this->assertNotSame([], $h->logger->lines);
    }

    public function testTheAdvisoryTextIsPassedAsDataNeverAsTemplate(): void
    {
        $evil = Fakes::stored('a/b', 'X');
        $evil = new \Ruvelo\SecurityAlerts\Service\StoredFinding($evil->key, 'a/b', '1.0.0', 'X', '{{ 7*7 }} {% endraw %} <script>', Severity::High);
        $h = new Harness(Fakes::store([$evil]));

        $h->notifier()->notifyPending();

        $data = $h->mail->sent[0]['data'];
        $this->assertSame('{{ ruvelo.html|raw }}', $data['contentHtml']);
        $this->assertSame('{{ ruvelo.text|raw }}', $data['contentPlain']);
        $this->assertStringNotContainsString('{{', (string) $data['subject']);
        $this->assertStringContainsString('&lt;script&gt;', (string) $h->mail->sent[0]['templateData']['ruvelo']['html']);
        $this->assertSame(['owner@example.com' => 'Shop owner'], $data['recipients']);
        $this->assertSame('shop@example.com', $data['senderMail']);
    }
}
