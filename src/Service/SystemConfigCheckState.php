<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

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
            'packages' => $report->packageCount(),
            'problems' => $report->problems,
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
        ];
    }
}
