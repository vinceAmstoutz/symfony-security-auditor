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

final class AuditedProjectConfigTest extends TestCase
{
    public function test_a_layered_file_keeps_what_it_sets_and_the_timeout_it_raises(): void
    {
        $auditedProjectConfig = AuditedProjectConfig::layered('/repo/.symfony-security-auditor.yaml', ['model' => 'm'], 900.0);

        self::assertSame('/repo/.symfony-security-auditor.yaml', $auditedProjectConfig->file);
        self::assertSame(['model' => 'm'], $auditedProjectConfig->config);
        self::assertSame(900.0, $auditedProjectConfig->httpTimeout);
        self::assertNull($auditedProjectConfig->skipReason);
        self::assertFalse($auditedProjectConfig->wasSkipped());
    }

    public function test_a_layered_file_may_raise_no_timeout(): void
    {
        self::assertNull(AuditedProjectConfig::layered('/repo/.symfony-security-auditor.yaml', [], null)->httpTimeout);
    }

    public function test_a_layered_file_names_the_baseline_it_sets_and_spells_it_for_the_container(): void
    {
        $auditedProjectConfig = AuditedProjectConfig::layered('/repo/.symfony-security-auditor.yaml', ['model' => 'm', 'audit' => ['fail_on' => 'high', 'baseline' => '/re%x%po/base%line.json']], null);

        self::assertSame('/re%x%po/base%line.json', $auditedProjectConfig->baseline());
        self::assertSame(['model' => 'm', 'audit' => ['fail_on' => 'high', 'baseline' => '/re%%x%%po/base%%line.json']], $auditedProjectConfig->configForContainer());
    }

    /**
     * @param array<array-key, mixed> $config
     */
    #[DataProvider('configsNamingNoBaseline')]
    public function test_a_layered_file_naming_no_baseline_is_handed_to_the_container_as_written(array $config): void
    {
        $auditedProjectConfig = AuditedProjectConfig::layered('/repo/.symfony-security-auditor.yaml', $config, null);

        self::assertNull($auditedProjectConfig->baseline());
        self::assertSame($config, $auditedProjectConfig->configForContainer());
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function configsNamingNoBaseline(): iterable
    {
        yield 'no audit section' => [['model' => '50%']];
        yield 'an audit section that is no map' => [['audit' => 'baseline']];
        yield 'an audit section without a baseline' => [['audit' => ['fail_on' => 'high']]];
        yield 'a baseline reset to null' => [['audit' => ['baseline' => null]]];
        yield 'a baseline that is no path' => [['audit' => ['baseline' => ['a%b%c']]]];
    }

    public function test_a_skipped_file_keeps_its_reason_and_contributes_nothing(): void
    {
        $auditedProjectConfig = AuditedProjectConfig::skipped('/repo/.symfony-security-auditor.yaml', 'declares "cache"');

        self::assertSame('/repo/.symfony-security-auditor.yaml', $auditedProjectConfig->file);
        self::assertSame([], $auditedProjectConfig->config);
        self::assertNull($auditedProjectConfig->httpTimeout);
        self::assertSame('declares "cache"', $auditedProjectConfig->skipReason);
        self::assertTrue($auditedProjectConfig->wasSkipped());
    }
}
