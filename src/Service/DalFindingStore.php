<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Entity\FindingCollection;
use Ruvelo\SecurityAlerts\Entity\FindingEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsAnyFilter;
use Shopware\Core\Framework\Uuid\Uuid;

class DalFindingStore implements FindingStore
{
    /**
     * @param EntityRepository<FindingCollection> $repository
     */
    public function __construct(private readonly EntityRepository $repository)
    {
    }

    public function known(): array
    {
        $known = [];
        foreach ($this->entities() as $entity) {
            $known[$entity->findingKey] = $entity->exploited;
        }

        return $known;
    }

    public function all(): array
    {
        $all = array_map($this->toStored(...), array_values($this->entities()));
        usort($all, StoredFinding::compare(...));

        return $all;
    }

    public function save(array $findings, array $resolved): void
    {
        $context = Context::createDefaultContext();
        $existing = [];
        foreach ($this->entities() as $entity) {
            $existing[$entity->findingKey] = $entity;
        }

        $upserts = [];
        foreach ($findings as $finding) {
            $old = $existing[$finding->key()] ?? null;
            $kev = $finding->exploited;
            $row = [
                'id' => $old?->getId() ?? Uuid::randomHex(),
                'findingKey' => $finding->key(),
                'package' => $finding->package,
                'installedVersion' => $finding->installed,
                'advisoryId' => $finding->advisoryId,
                'title' => $finding->title,
                'severity' => $finding->severity->value,
                'cve' => $finding->cve,
                'link' => $finding->link,
                'fixedIn' => $finding->fixedIn,
                // Once exploited, always exploited: an unreachable CISA feed must not lower the alarm.
                'exploited' => $finding->isExploited() || ($old !== null && $old->exploited),
                'isDev' => $finding->isDev,
            ];
            if ($kev !== null) {
                $row['kevAdded'] = $kev->dateAdded->format('Y-m-d');
                $row['kevDue'] = $kev->dueDate?->format('Y-m-d');
                $row['ransomware'] = $kev->ransomware;
            }
            if ($old === null) {
                $row['firstSeenAt'] = new \DateTimeImmutable();
            }
            $upserts[] = $row;
        }

        if ($upserts !== []) {
            $this->repository->upsert($upserts, $context);
        }

        $gone = [];
        foreach ($resolved as $key) {
            if (isset($existing[$key])) {
                $gone[] = ['id' => $existing[$key]->getId()];
            }
        }
        if ($gone !== []) {
            $this->repository->delete($gone, $context);
        }
    }

    public function pending(): array
    {
        return array_values(array_filter($this->all(), static fn (StoredFinding $f): bool => $f->isPending()));
    }

    public function markNotified(array $findings): void
    {
        if ($findings === []) {
            return;
        }

        $criteria = new Criteria();
        $criteria->addFilter(new EqualsAnyFilter('findingKey', array_map(static fn (StoredFinding $f): string => $f->key, $findings)));
        $now = new \DateTimeImmutable();
        $updates = [];
        foreach ($this->repository->search($criteria, Context::createDefaultContext())->getEntities() as $entity) {
            $updates[] = ['id' => $entity->getId(), 'notifiedAt' => $now, 'notifiedExploited' => $entity->exploited];
        }

        if ($updates !== []) {
            $this->repository->update($updates, Context::createDefaultContext());
        }
    }

    /**
     * @return array<string, FindingEntity>
     */
    private function entities(): array
    {
        $entities = [];
        foreach ($this->repository->search(new Criteria(), Context::createDefaultContext())->getEntities() as $entity) {
            $entities[$entity->getId()] = $entity;
        }

        return $entities;
    }

    private function toStored(FindingEntity $e): StoredFinding
    {
        return new StoredFinding(
            key: $e->findingKey,
            package: $e->package,
            installed: $e->installedVersion,
            advisoryId: $e->advisoryId,
            title: $e->title,
            severity: Severity::parse($e->severity),
            cve: $e->cve,
            link: $e->link,
            fixedIn: $e->fixedIn,
            exploited: $e->exploited,
            kevAdded: $e->kevAdded,
            kevDue: $e->kevDue,
            ransomware: $e->ransomware,
            isDev: $e->isDev,
            notified: $e->notifiedAt !== null,
            notifiedExploited: $e->notifiedExploited,
        );
    }
}
