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

use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\LLMConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationProcessor;

final class AuditConfigurationProcessorTest extends TestCase
{
    public function test_an_empty_configuration_receives_the_shipped_model_default(): void
    {
        $processed = (new AuditConfigurationProcessor())->process([]);

        self::assertSame(LLMConfiguration::DEFAULT_MODEL, $processed['model']);
    }

    public function test_an_explicit_value_survives_processing(): void
    {
        $processed = (new AuditConfigurationProcessor())->process(['model' => 'claude-haiku-4-5-20251001']);

        self::assertSame('claude-haiku-4-5-20251001', $processed['model']);
    }

    public function test_an_unknown_key_is_rejected_rather_than_silently_ignored(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        (new AuditConfigurationProcessor())->process(['not_a_real_key' => true]);
    }
}
