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

    /**
     * @param array<array-key, mixed> $auditConfig
     */
    private function config(array $auditConfig): StandaloneConfig
    {
        return new StandaloneConfig($auditConfig, new StandalonePlatformConfig([]));
    }
}
