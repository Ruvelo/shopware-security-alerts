<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Service;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Cache\CacheItemPoolInterface;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Symfony\Component\Cache\Psr16Cache;

/**
 * composer.lock through Packagist, plus the CISA exploited list. Guzzle is the
 * PSR-18 client (Shopware already ships it); the cache is Shopware's object cache.
 */
class HttpScannerProvider implements ScannerProvider
{
    public function __construct(
        private readonly string $projectDir,
        private readonly Settings $settings,
        private readonly CacheItemPoolInterface $cache,
    ) {
    }

    public function scanner(): Scanner
    {
        $factory = new HttpFactory();
        $http = new JsonClient(new Client(['timeout' => 20, 'connect_timeout' => 10]), $factory, $factory);
        $responses = new ResponseCache(new Psr16Cache($this->cache));

        return new Scanner(
            [new ComposerLockReader(rtrim($this->projectDir, '/\\').'/composer.lock', $this->settings->includeDev())],
            [new PackagistAdvisorySource($http, $responses)],
            new KevCatalogue($http, $responses),
        );
    }
}
