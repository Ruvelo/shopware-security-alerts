<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Service\SystemConfigSettings;

class SettingsTest extends TestCase
{
    public function testRecipientsAreSplitValidatedAndDeduplicated(): void
    {
        $this->assertSame(
            ['a@example.com', 'b@example.com'],
            SystemConfigSettings::parseRecipients("a@example.com, nope ;b@example.com\nA@EXAMPLE.COM")
        );
        $this->assertSame([], SystemConfigSettings::parseRecipients(''));
    }

    public function testSeverityFallsBackToMedium(): void
    {
        $this->assertSame(Severity::Critical, SystemConfigSettings::parseSeverity('critical'));
        $this->assertSame(Severity::Low, SystemConfigSettings::parseSeverity('low'));
        $this->assertSame(Severity::Medium, SystemConfigSettings::parseSeverity(''));
        $this->assertSame(Severity::Medium, SystemConfigSettings::parseSeverity('whatever'));
    }
}
