<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1791759600CreateFindingTable extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1791759600;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(<<<'SQL'
            CREATE TABLE IF NOT EXISTS `ruvelo_security_alerts_finding` (
                `id` BINARY(16) NOT NULL,
                `finding_key` VARCHAR(255) NOT NULL,
                `package` VARCHAR(255) NOT NULL,
                `installed_version` VARCHAR(255) NOT NULL,
                `advisory_id` VARCHAR(255) NOT NULL,
                `title` LONGTEXT NOT NULL,
                `severity` VARCHAR(32) NOT NULL,
                `cve` VARCHAR(64) NULL,
                `link` LONGTEXT NULL,
                `fixed_in` VARCHAR(255) NULL,
                `exploited` TINYINT(1) NOT NULL DEFAULT 0,
                `kev_added` VARCHAR(10) NULL,
                `kev_due` VARCHAR(10) NULL,
                `ransomware` TINYINT(1) NOT NULL DEFAULT 0,
                `is_dev` TINYINT(1) NOT NULL DEFAULT 0,
                `first_seen_at` DATETIME(3) NOT NULL,
                `notified_at` DATETIME(3) NULL,
                `notified_exploited` TINYINT(1) NOT NULL DEFAULT 0,
                `created_at` DATETIME(3) NOT NULL,
                `updated_at` DATETIME(3) NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `uniq.ruvelo_security_alerts_finding.key` (`finding_key`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        SQL);
    }
}
