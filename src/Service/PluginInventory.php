<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Plugin\PluginCollection;

class PluginInventory implements Inventory
{
    /**
     * @param EntityRepository<PluginCollection> $plugins
     */
    public function __construct(private readonly EntityRepository $plugins)
    {
    }

    public function notInstalledWithComposer(): ExtensionList
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('managedByComposer', false));
        $criteria->addSorting(new \Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting('name'));

        $list = [];
        foreach ($this->plugins->search($criteria, Context::createDefaultContext())->getEntities() as $plugin) {
            $list[] = ['name' => $plugin->getName(), 'version' => $plugin->getVersion()];
        }

        return new ExtensionList($list, Ecosystem::Extension, 'the Shopware plugins that are not installed with Composer');
    }
}
