<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Severity;
use Shopware\Core\System\SystemConfig\SystemConfigService;

class SystemConfigSettings implements Settings
{
    private const PREFIX = 'RuveloSecurityAlerts.config.';

    public function __construct(private readonly SystemConfigService $config)
    {
    }

    public function emailEnabled(): bool
    {
        $value = $this->config->get(self::PREFIX.'enabled');

        return $value === null ? true : (bool) $value;
    }

    public function recipients(): array
    {
        $raw = $this->config->get(self::PREFIX.'emails');

        return self::parseRecipients(is_string($raw) ? $raw : '');
    }

    public function minimumSeverity(): Severity
    {
        $raw = $this->config->get(self::PREFIX.'minimumSeverity');

        return self::parseSeverity(is_string($raw) ? $raw : '');
    }

    public function includeDev(): bool
    {
        return (bool) $this->config->get(self::PREFIX.'includeDev');
    }

    public function advisorySource(): string
    {
        $raw = $this->config->get(self::PREFIX.'advisorySource');

        return is_string($raw) && strtolower(trim($raw)) === Scanner::SOURCE_PUBLIC ? Scanner::SOURCE_PUBLIC : Scanner::SOURCE_VALTRY;
    }

    public function senderAddress(): ?string
    {
        foreach (['core.basicInformation.email', 'core.mailerSettings.senderAddress'] as $key) {
            $value = $this->config->get($key);
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    public static function parseRecipients(string $raw): array
    {
        $emails = [];
        foreach (preg_split('/[\s,;]+/', $raw) ?: [] as $candidate) {
            if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_EMAIL) !== false) {
                $emails[strtolower($candidate)] ??= $candidate;
            }
        }

        return array_values($emails);
    }

    /** Anything unrecognised means medium, the default. */
    public static function parseSeverity(string $raw): Severity
    {
        $severity = Severity::parse($raw);

        return $severity === Severity::NotRated ? Severity::Medium : $severity;
    }
}
