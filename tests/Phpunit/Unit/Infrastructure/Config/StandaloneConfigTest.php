<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditedProjectConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;

final class StandaloneConfigTest extends TestCase
{
    public function test_offline_only_is_on_when_the_audit_config_asks_for_it(): void
    {
        self::assertTrue($this->config(['privacy' => ['offline_only' => true]])->offlineOnly());
    }

    /**
     * @param array<array-key, mixed> $auditConfig
     */
    #[DataProvider('nonOfflineConfigCases')]
    public function test_offline_only_is_off_otherwise(array $auditConfig): void
    {
        self::assertFalse($this->config($auditConfig)->offlineOnly());
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function nonOfflineConfigCases(): iterable
    {
        yield 'no privacy section' => [[]];
        yield 'explicitly disabled' => [['privacy' => ['offline_only' => false]]];
        yield 'empty privacy section' => [['privacy' => []]];
        yield 'privacy is not a map' => [['privacy' => 'yes']];
        yield 'truthy but not true' => [['privacy' => ['offline_only' => 1]]];
    }

    public function test_it_gets_the_audited_project_config_without_losing_anything_else(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['ollama' => []], 'ollama');
        $auditedProjectConfig = AuditedProjectConfig::skipped('/repo/.symfony-security-auditor.yaml', 'not valid YAML');
        $standaloneConfig = new StandaloneConfig(['model' => 'm'], $standalonePlatformConfig, '/work/.symfony-security-auditor.yaml', 900.0);

        $withTheAuditedProject = $standaloneConfig->withAuditedProjectConfig($auditedProjectConfig);

        self::assertNull($standaloneConfig->auditedProjectConfig);
        self::assertSame($auditedProjectConfig, $withTheAuditedProject->auditedProjectConfig);
        self::assertSame(['model' => 'm'], $withTheAuditedProject->auditConfig);
        self::assertSame($standalonePlatformConfig, $withTheAuditedProject->platform);
        self::assertSame('/work/.symfony-security-auditor.yaml', $withTheAuditedProject->projectConfigFile);
        self::assertSame(900.0, $withTheAuditedProject->httpTimeout);
    }

    public function test_it_drops_the_audited_project_config_when_given_none(): void
    {
        $standaloneConfig = $this->config([])->withAuditedProjectConfig(AuditedProjectConfig::layered('/repo/.symfony-security-auditor.yaml', [], null));

        self::assertNull($standaloneConfig->withAuditedProjectConfig(null)->auditedProjectConfig);
    }

    /**
     * @param array<array-key, mixed> $auditConfig
     */
    private function config(array $auditConfig): StandaloneConfig
    {
        return new StandaloneConfig($auditConfig, new StandalonePlatformConfig([]));
    }
}
