<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\ScheduledTask;

use Shopware\Core\Framework\MessageQueue\ScheduledTask\ScheduledTask;

class CheckTask extends ScheduledTask
{
    public const NAME = 'ruvelo.security_alerts.check';

    public static function getTaskName(): string
    {
        return self::NAME;
    }

    public static function getDefaultInterval(): int
    {
        return self::DAILY;
    }
}
