<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Migration\Migration1791759600CreateFindingTable;
use Ruvelo\SecurityAlerts\ScheduledTask\CheckTask;

/**
 * What a real install would trip over first, checked without one.
 */
class WiringTest extends TestCase
{
    private const ROOT = __DIR__.'/../..';

    public function testComposerMetadataIsWhatShopwareNeeds(): void
    {
        $c = json_decode((string) file_get_contents(self::ROOT.'/composer.json'), true, flags: JSON_THROW_ON_ERROR);

        $this->assertSame('shopware-platform-plugin', $c['type']);
        $this->assertSame('ruvelo/shopware-security-alerts', $c['name']);
        $this->assertSame('Ruvelo\\SecurityAlerts\\RuveloSecurityAlerts', $c['extra']['shopware-plugin-class']);
        $this->assertTrue(class_exists($c['extra']['shopware-plugin-class']));
        $this->assertSame('RuveloSecurityAlerts', (new \ReflectionClass($c['extra']['shopware-plugin-class']))->getShortName());
        $this->assertArrayHasKey('en-GB', $c['extra']['label']);
        $this->assertArrayHasKey('de-DE', $c['extra']['label']);
        $this->assertArrayNotHasKey('repositories', $c, 'the core is added by CI only, never published');
        $this->assertSame('^1.0', $c['require']['ruvelo/security-advisories']);
    }

    public function testEveryServiceClassExists(): void
    {
        $xml = simplexml_load_file(self::ROOT.'/src/Resources/config/services.xml');
        $this->assertNotFalse($xml);
        $xml->registerXPathNamespace('s', 'http://symfony.com/schema/dic/services');
        $ids = $xml->xpath('//s:service[starts-with(@id, "Ruvelo")]') ?: [];

        $this->assertNotSame([], $ids);
        foreach ($ids as $service) {
            $id = (string) $service['id'];
            $this->assertTrue(class_exists($id) || interface_exists($id), "$id is not a class");
        }
    }

    public function testTheScheduledTaskIsDailyAndNamed(): void
    {
        $this->assertSame('ruvelo.security_alerts.check', CheckTask::getTaskName());
        $this->assertSame(86400, CheckTask::getDefaultInterval());
        $this->assertStringContainsString('shopware.scheduled.task', (string) file_get_contents(self::ROOT.'/src/Resources/config/services.xml'));
    }

    public function testConfigDeclaresTheKeysTheSettingsReadAndIsValidXml(): void
    {
        $xml = simplexml_load_file(self::ROOT.'/src/Resources/config/config.xml');
        $this->assertNotFalse($xml);
        $names = array_map('strval', $xml->xpath('//input-field/name') ?: []);
        $this->assertSame(['enabled', 'emails', 'minimumSeverity', 'includeDev'], $names);
    }

    public function testTheMigrationCreatesTheTableTheDefinitionNames(): void
    {
        $migration = new Migration1791759600CreateFindingTable();
        $this->assertSame(1791759600, $migration->getCreationTimestamp());

        $sql = (string) file_get_contents((string) (new \ReflectionClass($migration))->getFileName());
        $this->assertStringContainsString('`ruvelo_security_alerts_finding`', $sql);
        $this->assertSame('ruvelo_security_alerts_finding', \Ruvelo\SecurityAlerts\Entity\FindingDefinition::ENTITY_NAME);
    }

    public function testRoutesAreGuardedByTheAclPrivilegesTheAdminDeclares(): void
    {
        $controller = (string) file_get_contents(self::ROOT.'/src/Controller/SecurityAlertsController.php');
        $acl = (string) file_get_contents(self::ROOT.'/src/Resources/app/administration/src/module/ruvelo-security-alerts/acl/index.js');

        foreach (['ruvelo_security_alerts:read', 'ruvelo_security_alerts:check'] as $privilege) {
            $this->assertStringContainsString("'$privilege'", $controller);
            $this->assertStringContainsString("'$privilege'", $acl);
        }
    }

    public function testAdministrationSourceIsCommittedAndSnippetsAreInStep(): void
    {
        $base = self::ROOT.'/src/Resources/app/administration/src';
        $this->assertFileExists($base.'/main.js');

        $en = json_decode((string) file_get_contents($base.'/module/ruvelo-security-alerts/snippet/en-GB.json'), true, flags: JSON_THROW_ON_ERROR);
        $de = json_decode((string) file_get_contents($base.'/module/ruvelo-security-alerts/snippet/de-DE.json'), true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame($this->keys($en), $this->keys($de));
    }

    /**
     * @param array<mixed> $a
     * @return list<string>
     */
    private function keys(array $a, string $prefix = ''): array
    {
        $out = [];
        foreach ($a as $k => $v) {
            is_array($v) ? array_push($out, ...$this->keys($v, "$prefix$k.")) : $out[] = "$prefix$k";
        }
        sort($out);

        return $out;
    }
}
