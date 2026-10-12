<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

/**
 * The email, plain and HTML, exploited first. Pure text building: the Notifier sends it.
 */
final class MailContent
{
    /**
     * @param list<StoredFinding> $findings
     */
    public static function subject(array $findings): string
    {
        $exploited = count(array_filter($findings, static fn (StoredFinding $f): bool => $f->exploited));

        if ($exploited > 0) {
            return sprintf(
                'Exploited — patch now: %d known %s on your Shopware shop',
                $exploited,
                $exploited === 1 ? 'vulnerability is being exploited' : 'vulnerabilities are being exploited'
            );
        }

        return sprintf('%d new security %s for your Shopware shop', count($findings), count($findings) === 1 ? 'advisory' : 'advisories');
    }

    /**
     * @param list<StoredFinding> $findings
     */
    public static function text(array $findings): string
    {
        $lines = [];
        foreach (self::sorted($findings) as $f) {
            $lines[] = ($f->exploited ? 'EXPLOITED — PATCH NOW: ' : strtoupper($f->severity->label()).': ').$f->title;
            $lines[] = '  '.implode(' · ', self::facts($f));
            if ($f->link !== null && self::isWebLink($f->link)) {
                $lines[] = '  '.$f->link;
            }
            $lines[] = '';
        }

        return trim(implode("\n", $lines))."\n\nThese are advisories for packages in your composer.lock. Update them, then run bin/console ruvelo:security-alerts:check.";
    }

    /**
     * @param list<StoredFinding> $findings
     */
    public static function html(array $findings): string
    {
        $html = '';
        foreach (self::sorted($findings) as $f) {
            $title = self::e($f->title);
            if ($f->link !== null && self::isWebLink($f->link)) {
                $title = '<a href="'.self::e($f->link).'">'.$title.'</a>';
            }
            $badge = $f->exploited ? '<strong style="color:#c0152f">Exploited — patch now</strong><br>' : '';
            $html .= '<p style="margin:0 0 14px">'.$badge.'<strong>'.$title.'</strong><br>'
                .implode(' · ', array_map(self::e(...), self::facts($f))).'</p>';
        }

        return $html.'<p style="color:#74748b">These are advisories for packages in your composer.lock. Update them, then run <code>bin/console ruvelo:security-alerts:check</code>.</p>';
    }

    /**
     * @param list<StoredFinding> $findings
     * @return list<StoredFinding>
     */
    private static function sorted(array $findings): array
    {
        usort($findings, StoredFinding::compare(...));

        return $findings;
    }

    /**
     * @return list<string>
     */
    private static function facts(StoredFinding $f): array
    {
        $facts = [$f->package.' '.$f->installed];
        if ($f->cve !== null) {
            $facts[] = $f->cve;
        }
        $facts[] = $f->severity->label();
        $facts[] = $f->fixedIn !== null ? 'fixed in '.$f->fixedIn : 'no fixed version listed';

        return $facts;
    }

    private static function isWebLink(string $link): bool
    {
        return preg_match('#^https?://#i', $link) === 1;
    }

    private static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
