<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Entity;

use Shopware\Core\Framework\DataAbstractionLayer\EntityCollection;

/**
 * @extends EntityCollection<FindingEntity>
 */
class FindingCollection extends EntityCollection
{
    protected function getExpectedClass(): string
    {
        return FindingEntity::class;
    }
}
