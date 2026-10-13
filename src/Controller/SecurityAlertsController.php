<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Controller;

use Ruvelo\SecurityAlerts\Service\CheckState;
use Ruvelo\SecurityAlerts\Service\Checker;
use Ruvelo\SecurityAlerts\Service\FindingStore;
use Ruvelo\SecurityAlerts\Service\StoredFinding;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

#[Route(defaults: ['_routeScope' => ['api']])]
class SecurityAlertsController extends AbstractController
{
    public function __construct(
        private readonly Checker $checker,
        private readonly FindingStore $store,
        private readonly CheckState $state,
    ) {
    }

    #[Route(path: '/api/_action/ruvelo-security-alerts/findings', name: 'api.action.ruvelo_security_alerts.findings', defaults: ['_acl' => ['ruvelo_security_alerts:read']], methods: ['GET'])]
    public function findings(): JsonResponse
    {
        return new JsonResponse($this->payload());
    }

    #[Route(path: '/api/_action/ruvelo-security-alerts/check', name: 'api.action.ruvelo_security_alerts.check', defaults: ['_acl' => ['ruvelo_security_alerts:check']], methods: ['POST'])]
    public function check(): JsonResponse
    {
        $this->checker->run(true);

        return new JsonResponse($this->payload());
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(): array
    {
        $last = $this->state->last();

        return [
            'findings' => array_map(static fn (StoredFinding $f): array => $f->toArray(), $this->store->all()),
            'not_checked' => $last['not_checked'] ?? [],
            'last_check' => $last,
        ];
    }
}
