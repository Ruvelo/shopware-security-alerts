<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Psr\Log\LoggerInterface;
use Shopware\Core\Content\Mail\Service\AbstractMailService;
use Shopware\Core\Framework\Context;

/**
 * Emails what nobody has been told about yet: new findings, and ones that have become exploited.
 */
class Notifier
{
    public function __construct(
        private readonly Settings $settings,
        private readonly FindingStore $store,
        private readonly AbstractMailService $mail,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @return int How many findings went into the email
     */
    public function notifyPending(): int
    {
        $recipients = $this->settings->recipients();
        if (! $this->settings->emailEnabled() || $recipients === []) {
            // Nothing is marked, so turning email on later still reports what is open.
            return 0;
        }

        $pending = $this->store->pending();
        if ($pending === []) {
            return 0;
        }

        // Exploited findings are always sent. The minimum severity filters the rest, and a finding
        // below it is marked as handled so it is not reconsidered every day.
        $minimum = $this->settings->minimumSeverity()->rank();
        $toSend = array_values(array_filter($pending, static fn (StoredFinding $f): bool => $f->exploited || $f->severity->rank() >= $minimum));

        if ($toSend !== []) {
            try {
                $sent = $this->send($toSend, $recipients);
            } catch (\Throwable $e) {
                $this->logger->error('Ruvelo Security Alerts: the email could not be sent: '.$e->getMessage());

                return 0;
            }

            if (! $sent) {
                $this->logger->error('Ruvelo Security Alerts: the mail service did not send the email, see the Shopware log. Will try again next check.');

                return 0;
            }
        }

        $this->store->markNotified($pending);

        return count($toSend);
    }

    /**
     * @param list<StoredFinding> $findings
     * @param list<string> $recipients
     */
    private function send(array $findings, array $recipients): bool
    {
        $data = [
            'recipients' => array_fill_keys($recipients, 'Shop owner'),
            'senderName' => 'Security alerts',
            'senderMail' => $this->settings->senderAddress() ?? $recipients[0],
            'subject' => MailContent::subject($findings),
            // The advisory text is data, never template: it goes in as variables.
            'contentHtml' => '{{ ruvelo.html|raw }}',
            'contentPlain' => '{{ ruvelo.text|raw }}',
        ];

        $message = $this->mail->send($data, Context::createDefaultContext(), [
            'ruvelo' => ['html' => MailContent::html($findings), 'text' => MailContent::text($findings)],
        ]);

        return $message !== null;
    }
}
