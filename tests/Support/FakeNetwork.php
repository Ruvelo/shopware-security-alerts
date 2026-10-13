<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Support;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

/**
 * Valtry's Advisory API (answers signed with a key made for the test), Packagist and CISA KEV,
 * all served from memory. Nothing touches the network; $stray lists anything else asked for.
 */
final class FakeNetwork implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];
    /** @var list<string> */
    public array $stray = [];
    /** @var array<string, string> */
    public array $keys;
    public bool $valtryDown = false;
    /** @var list<array<mixed>> */
    public array $valtryBodies = [];

    /** @var non-empty-string */
    private string $secretKey;
    private Psr17Factory $factory;

    /**
     * @param list<array<string, mixed>> $advisories Each: package, id, cve, affected, title, valtryId (what Valtry calls it, default id)
     * @param list<string> $exploited CVEs CISA lists
     */
    public function __construct(public array $advisories = [], public array $exploited = [])
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->keys = ['test-1' => base64_encode(sodium_crypto_sign_publickey($pair))];
        $this->factory = new Psr17Factory();
    }

    public function sentTo(string $needle): int
    {
        return count(array_filter($this->requests, static fn (RequestInterface $r): bool => str_contains((string) $r->getUri(), $needle)));
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $url = (string) $request->getUri();

        if (str_starts_with($url, ValtryAdvisorySource::URL)) {
            return $this->valtryDown ? $this->json([], 503) : $this->valtry($request);
        }
        if (str_contains($url, 'packagist.org/api/security-advisories')) {
            return $this->packagist($request);
        }
        if (str_contains($url, 'cisa.gov')) {
            return $this->kev();
        }

        $this->stray[] = $request->getMethod().' '.$url;

        return $this->json([], 404);
    }

    private function valtry(RequestInterface $request): ResponseInterface
    {
        $body = json_decode((string) $request->getBody(), true);
        $body = is_array($body) ? $body : [];
        $this->valtryBodies[] = $body;

        $answer = [];
        foreach ($body['packages'] ?? [] as $p) {
            $list = [];
            foreach ($this->advisories as $a) {
                if (strtolower($a['package']) === $p['name']) {
                    $kev = isset($a['cve']) && in_array($a['cve'], $this->exploited, true);
                    $list[] = [
                        'id' => $a['valtryId'] ?? $a['id'], 'source' => 'packagist', 'title' => $a['title'], 'link' => 'https://example.com/'.$a['id'],
                        'cve' => $a['cve'] ?? null, 'aliases' => [], 'severity' => $a['severity'] ?? 'high', 'affected' => $a['affected'], 'fixed_in' => [],
                        'exploited' => $kev,
                        'kev' => $kev ? ['cve' => $a['cve'], 'name' => 'Exploited thing', 'date_added' => '2026-10-01', 'due_date' => '2026-10-22', 'ransomware' => false] : null,
                        'published_at' => '2026-09-01T00:00:00Z', 'updated_at' => null, 'attribution' => null,
                    ];
                }
            }
            $answer[$p['ecosystem'].':'.$p['name']] = $list;
        }

        $json = (string) json_encode([
            'v' => 1, 'generated_at' => gmdate('Y-m-d\TH:i:s\Z'), 'nonce' => $body['nonce'] ?? null,
            'advisories' => (object) $answer, 'sources' => [], 'stale' => false, 'stale_sources' => [], 'stale_ecosystems' => [],
        ], JSON_UNESCAPED_SLASHES);
        $signature = 'ed25519='.base64_encode(sodium_crypto_sign_detached($json, $this->secretKey)).'; kid=test-1';

        return $this->json($json)->withHeader('X-Valtry-Signature', $signature);
    }

    private function packagist(RequestInterface $request): ResponseInterface
    {
        parse_str((string) $request->getBody(), $form);
        $names = array_map('strtolower', (array) ($form['packages'] ?? []));

        $out = [];
        foreach ($this->advisories as $a) {
            if (in_array(strtolower($a['package']), $names, true)) {
                $out[strtolower($a['package'])][] = [
                    'advisoryId' => $a['id'], 'packageName' => strtolower($a['package']), 'title' => $a['title'], 'link' => 'https://example.com/'.$a['id'],
                    'cve' => $a['cve'] ?? null, 'severity' => $a['severity'] ?? 'high', 'affectedVersions' => $a['affected'], 'reportedAt' => '2026-09-01 00:00:00',
                ];
            }
        }

        return $this->json(['advisories' => (object) $out]);
    }

    private function kev(): ResponseInterface
    {
        return $this->json(['vulnerabilities' => array_map(static fn (string $cve): array => [
            'cveID' => $cve, 'vulnerabilityName' => 'Exploited thing', 'dateAdded' => '2026-10-01', 'dueDate' => '2026-10-22', 'knownRansomwareCampaignUse' => 'Unknown',
        ], $this->exploited)]);
    }

    /**
     * @param array<mixed>|string $body
     */
    private function json(array|string $body, int $status = 200): ResponseInterface
    {
        return $this->factory->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->factory->createStream(is_string($body) ? $body : (string) json_encode($body)));
    }
}
