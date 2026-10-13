<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;
use Symfony\Component\Cache\Psr16Cache;

/**
 * composer.lock and the plugins that are not Composer packages, through the
 * core's usual composition: Valtry's signed Advisory API first, Packagist and
 * the CISA exploited list directly whenever Valtry cannot answer (or when the
 * "Advisory source" setting, or RUVELO_ADVISORIES_SOURCE=public, says so).
 * Guzzle is the PSR-18 client (Shopware already ships it); the cache is Shopware's object cache.
 */
class HttpScannerProvider implements ScannerProvider
{
    /**
     * @param ClientInterface|null $client Replaces Guzzle (tests)
     * @param array<string, string>|null $valtryKeys Replaces the keys pinned in the core (tests, which sign their own answers)
     */
    public function __construct(
        private readonly string $projectDir,
        private readonly Settings $settings,
        private readonly CacheItemPoolInterface $cache,
        private readonly ?Inventory $inventory = null,
        private readonly ?ClientInterface $client = null,
        private readonly ?array $valtryKeys = null,
    ) {
    }

    public function scanner(): Scanner
    {
        $factory = new HttpFactory();
        $http = new JsonClient($this->client ?? new Client(['timeout' => 20, 'connect_timeout' => 10, 'http_errors' => false]), $factory, $factory);
        $responses = new ResponseCache(new Psr16Cache($this->cache));

        $public = [new PackagistAdvisorySource($http, $responses)];
        $advisories = Scanner::source($this->settings->advisorySource()) === Scanner::SOURCE_PUBLIC
            ? $public
            : [new FallbackAdvisorySource(
                new ValtryAdvisorySource(
                    new JsonClient($this->client ?? new Client(['timeout' => ValtryAdvisorySource::DEADLINE, 'connect_timeout' => ValtryAdvisorySource::DEADLINE, 'http_errors' => false]), $factory, $factory, JsonClient::USER_AGENT, 1),
                    $responses,
                    ValtryAdvisorySource::URL,
                    $this->valtryKeys,
                ),
                $public,
            )];

        $readers = [new ComposerLockReader(rtrim($this->projectDir, '/\\').'/composer.lock', $this->settings->includeDev())];
        if ($this->inventory !== null) {
            // Plugins unpacked from a zip are no Composer packages: the report lists them as unchecked.
            $readers[] = $this->inventory->notInstalledWithComposer();
        }

        return new Scanner($readers, $advisories, new KevCatalogue($http, $responses));
    }
}
