<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Plugin;
use Shopware\Core\Framework\Plugin\Context\UninstallContext;

class RuveloSecurityAlerts extends Plugin
{
    public function uninstall(UninstallContext $uninstallContext): void
    {
        if ($uninstallContext->keepUserData()) {
            return;
        }

        $connection = $this->container?->get(Connection::class);
        if ($connection instanceof Connection) {
            $connection->executeStatement('DROP TABLE IF EXISTS `ruvelo_security_alerts_finding`');
        }
    }
}
