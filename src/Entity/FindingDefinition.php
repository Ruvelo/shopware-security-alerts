<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Entity;

use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\BoolField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\DateTimeField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\LongTextField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

class FindingDefinition extends EntityDefinition
{
    public const ENTITY_NAME = 'ruvelo_security_alerts_finding';

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getCollectionClass(): string
    {
        return FindingCollection::class;
    }

    public function getEntityClass(): string
    {
        return FindingEntity::class;
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new PrimaryKey(), new Required()),
            (new StringField('finding_key', 'findingKey'))->addFlags(new Required()),
            (new StringField('package', 'package'))->addFlags(new Required()),
            (new StringField('installed_version', 'installedVersion'))->addFlags(new Required()),
            (new StringField('advisory_id', 'advisoryId'))->addFlags(new Required()),
            (new LongTextField('title', 'title'))->addFlags(new Required()),
            (new StringField('severity', 'severity', 32))->addFlags(new Required()),
            new StringField('cve', 'cve', 64),
            new LongTextField('link', 'link'),
            new StringField('fixed_in', 'fixedIn'),
            new BoolField('exploited', 'exploited'),
            new StringField('kev_added', 'kevAdded', 10),
            new StringField('kev_due', 'kevDue', 10),
            new BoolField('ransomware', 'ransomware'),
            new BoolField('is_dev', 'isDev'),
            (new DateTimeField('first_seen_at', 'firstSeenAt'))->addFlags(new Required()),
            new DateTimeField('notified_at', 'notifiedAt'),
            new BoolField('notified_exploited', 'notifiedExploited'),
            new LongTextField('last_seen', 'lastSeen'),
        ]);
    }
}
