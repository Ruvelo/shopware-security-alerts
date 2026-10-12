<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Support;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAlerts\Service\CheckState;
use Ruvelo\SecurityAlerts\Service\Checker;
use Ruvelo\SecurityAlerts\Service\Inventory;
use Ruvelo\SecurityAlerts\Service\Notifier;
use Ruvelo\SecurityAlerts\Service\ScannerProvider;
use Shopware\Core\Content\Mail\Service\AbstractMailService;
use Shopware\Core\Framework\Context;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Mime\Email;

/**
 * Wires a Checker from fakes, over tests/fixtures/composer.lock. No Shopware, no network.
 */
final class Harness
{
    public FakeAdvisories $advisories;
    public FakeKev $kev;
    public MemoryStore $store;
    public FakeSettings $settings;
    public RecordingMail $mail;
    public MemoryLogger $logger;
    public EventDispatcher $events;
    public Checker $checker;
    /** @var list<array{string, string}> */
    public array $zipPlugins = [['Acme_Zip', '1.2.3']];
    public ?Report $recorded = null;

    public function __construct(?MemoryStore $store = null, ?FakeSettings $settings = null)
    {
        $this->advisories = new FakeAdvisories();
        $this->kev = new FakeKev();
        $this->store = $store ?? new MemoryStore();
        $this->settings = $settings ?? new FakeSettings();
        $this->mail = new RecordingMail();
        $this->logger = new MemoryLogger();
        $this->events = new EventDispatcher();

        $self = $this;
        $scanners = new class ($self) implements ScannerProvider {
            public function __construct(private readonly Harness $h)
            {
            }

            public function scanner(): Scanner
            {
                return new Scanner([new ComposerLockReader(__DIR__.'/../fixtures/composer.lock', false)], [$this->h->advisories], $this->h->kev);
            }
        };
        $inventory = new class ($self) implements Inventory {
            public function __construct(private readonly Harness $h)
            {
            }

            public function notInstalledWithComposer(): ExtensionList
            {
                return new ExtensionList(array_map(static fn (array $p): array => ['name' => $p[0], 'version' => $p[1]], $this->h->zipPlugins), Ecosystem::Extension);
            }
        };
        $state = new class ($self) implements CheckState {
            public function __construct(private readonly Harness $h)
            {
            }

            public function record(Report $report): void
            {
                $this->h->recorded = $report;
            }

            public function last(): ?array
            {
                return null;
            }
        };

        $notifier = new Notifier($this->settings, $this->store, $this->mail, $this->logger);
        $this->checker = new Checker($scanners, $this->store, $inventory, $notifier, $state, $this->events);
    }

    public function notifier(): Notifier
    {
        return new Notifier($this->settings, $this->store, $this->mail, $this->logger);
    }
}

final class RecordingMail extends AbstractMailService
{
    /** @var list<array{data: array<string, mixed>, templateData: array<string, mixed>}> */
    public array $sent = [];
    public bool $fail = false;

    public function getDecorated(): AbstractMailService
    {
        throw new \LogicException('not decorated');
    }

    public function send(array $data, Context $context, array $templateData = []): ?Email
    {
        if ($this->fail) {
            return null;
        }
        $this->sent[] = ['data' => $data, 'templateData' => $templateData];

        return new Email();
    }
}
