<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Service\MailContent;
use Ruvelo\SecurityAlerts\Service\StoredFinding;
use Ruvelo\SecurityAlerts\Tests\Support\Fakes;

class MailContentTest extends TestCase
{
    public function testTheSubjectLeadsWithExploited(): void
    {
        $this->assertSame('Exploited — patch now: 1 known vulnerability is being exploited on your Shopware shop', MailContent::subject([Fakes::stored('a/b', '1', exploited: true), Fakes::stored('c/d', '2')]));
        $this->assertSame('2 new security advisories for your Shopware shop', MailContent::subject([Fakes::stored('a/b', '1'), Fakes::stored('c/d', '2')]));
        $this->assertSame('1 new security advisory for your Shopware shop', MailContent::subject([Fakes::stored('a/b', '1')]));
    }

    public function testHtmlEscapesTitlesAndOnlyLinksWebUrls(): void
    {
        $f = new StoredFinding('k', 'a/b', '1.0.0', 'X', '<b>Bad</b> & worse', Severity::High, 'CVE-1', 'javascript:alert(1)');
        $html = MailContent::html([$f]);

        $this->assertStringContainsString('&lt;b&gt;Bad&lt;/b&gt; &amp; worse', $html);
        $this->assertStringNotContainsString('href="javascript', $html);
        $this->assertStringContainsString('no fixed version listed', $html);
    }

    public function testExploitedItemsComeFirstInBothFormats(): void
    {
        $list = [Fakes::stored('a/high', 'H'), Fakes::stored('b/exploited', 'E', Severity::Low, exploited: true)];

        foreach ([MailContent::text($list), MailContent::html($list)] as $body) {
            $this->assertLessThan(strpos($body, 'a/high'), strpos($body, 'b/exploited'));
        }
        $this->assertStringContainsString('Exploited — patch now', MailContent::html($list));
    }

    public function testItNeverMentionsAnythingElse(): void
    {
        $body = MailContent::text([Fakes::stored('a/b', '1')]).MailContent::html([Fakes::stored('a/b', '1')]);
        $this->assertStringNotContainsStringIgnoringCase('valtry', $body);
    }
}
