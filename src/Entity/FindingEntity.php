<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Entity;

use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityIdTrait;

class FindingEntity extends Entity
{
    use EntityIdTrait;

    public string $findingKey = '';
    public string $package = '';
    public string $installedVersion = '';
    public string $advisoryId = '';
    public string $title = '';
    public string $severity = 'not_rated';
    public ?string $cve = null;
    public ?string $link = null;
    public ?string $fixedIn = null;
    public bool $exploited = false;
    public ?string $kevAdded = null;
    public ?string $kevDue = null;
    public bool $ransomware = false;
    public bool $isDev = false;
    public ?\DateTimeInterface $firstSeenAt = null;
    public ?\DateTimeInterface $notifiedAt = null;
    public bool $notifiedExploited = false;
}
