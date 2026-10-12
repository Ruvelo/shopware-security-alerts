<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Packages\ExtensionList;

interface Inventory
{
    /**
     * Plugins that are not installed with Composer (zips under custom/plugins):
     * they are listed, but no advisory feed covers them.
     */
    public function notInstalledWithComposer(): ExtensionList;
}
