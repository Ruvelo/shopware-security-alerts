<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Note;
use Ruvelo\SecurityAdvisories\Report;
use Shopware\Core\System\SystemConfig\SystemConfigService;

class SystemConfigCheckState implements CheckState
{
    private const KEY = 'RuveloSecurityAlerts.state.last';

    public function __construct(private readonly SystemConfigService $config)
    {
    }

    public function record(Report $report): void
    {
        $this->config->set(self::KEY, [
            'checked_at' => $report->checkedAt?->format(\DATE_ATOM),
            'complete' => $report->isComplete(),
            'kev_checked' => $report->kevChecked,
            'packages' => $report->packageCount(Ecosystem::Composer),
            'problems' => $report->problems,
            'source' => $report->source,
            'sources' => $report->sources,
            'not_checked' => CheckOutcome::notCheckedRows($report),
            'notes' => array_map(static fn (Note $n): string => ($n->package !== null ? $n->package.': ' : '').$n->message, $report->notes),
        ]);
    }

    public function last(): ?array
    {
        $value = $this->config->get(self::KEY);
        if (! is_array($value)) {
            return null;
        }

        return [
            'checked_at' => is_string($value['checked_at'] ?? null) ? $value['checked_at'] : null,
            'complete' => (bool) ($value['complete'] ?? false),
            'kev_checked' => (bool) ($value['kev_checked'] ?? false),
            'packages' => (int) ($value['packages'] ?? 0),
            'problems' => array_values(array_filter((array) ($value['problems'] ?? []), 'is_string')),
            // A check stored by 1.0 did not say: it only had the public feeds.
            'source' => is_string($value['source'] ?? null) ? $value['source'] : 'public',
            'sources' => array_filter((array) ($value['sources'] ?? []), 'is_string'),
            'not_checked' => $this->rows($value['not_checked'] ?? null),
            'notes' => array_values(array_filter((array) ($value['notes'] ?? []), 'is_string')),
        ];
    }

    /**
     * @return list<array{name: string, version: string, reason: string}>
     */
    private function rows(mixed $raw): array
    {
        $rows = [];
        foreach (is_array($raw) ? $raw : [] as $row) {
            if (is_array($row) && is_string($row['name'] ?? null)) {
                $rows[] = ['name' => $row['name'], 'version' => is_string($row['version'] ?? null) ? $row['version'] : '', 'reason' => is_string($row['reason'] ?? null) ? $row['reason'] : CheckOutcome::NOT_CHECKED];
            }
        }

        return $rows;
    }
}
