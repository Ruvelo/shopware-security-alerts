<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\ScheduledTask;

use Psr\Log\LoggerInterface;
use Ruvelo\SecurityAlerts\Service\Checker;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\MessageQueue\ScheduledTask\ScheduledTaskHandler;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler(handles: CheckTask::class)]
class CheckTaskHandler extends ScheduledTaskHandler
{
    /**
     * @param EntityRepository<\Shopware\Core\Framework\MessageQueue\ScheduledTask\ScheduledTaskCollection> $scheduledTaskRepository
     */
    public function __construct(
        EntityRepository $scheduledTaskRepository,
        LoggerInterface $logger,
        private readonly Checker $checker,
        private readonly LoggerInterface $log,
    ) {
        parent::__construct($scheduledTaskRepository, $logger);
    }

    public function run(): void
    {
        try {
            $this->checker->run();
        } catch (\Throwable $e) {
            // A failed check must not make the queue retry in a loop; the next run tries again.
            $this->log->error('Ruvelo Security Alerts: the daily check failed: '.$e->getMessage());
        }
    }
}
