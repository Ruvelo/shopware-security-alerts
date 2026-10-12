<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Scanner;

interface ScannerProvider
{
    public function scanner(): Scanner;
}
