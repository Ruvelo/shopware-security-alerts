<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Keeps the finding as last seen beside each row, so the same flaw named
 * differently by another source (Valtry or the public feeds) is recognised.
 */
class Migration1791846000AddLastSeenToFinding extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1791846000;
    }

    public function update(Connection $connection): void
    {
        $has = $connection->fetchOne(
            'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c',
            ['t' => 'ruvelo_security_alerts_finding', 'c' => 'last_seen'],
        );

        if ((int) $has === 0) {
            $connection->executeStatement('ALTER TABLE `ruvelo_security_alerts_finding` ADD COLUMN `last_seen` LONGTEXT NULL');
        }
    }
}
