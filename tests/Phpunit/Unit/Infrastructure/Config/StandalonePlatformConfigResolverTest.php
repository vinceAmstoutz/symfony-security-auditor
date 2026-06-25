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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;

final class StandalonePlatformConfigResolverTest extends TestCase
{
    public function test_it_resolves_the_provider_and_a_literal_api_key(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['provider' => 'anthropic', 'api_key' => 'sk-literal']);

        self::assertSame(['anthropic' => ['api_key' => 'sk-literal']], $platformConfig->toAiPlatformConfig());
    }

    public function test_it_resolves_an_env_placeholder_api_key_from_the_environment(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY' => 'sk-from-env']))
            ->resolve(['provider' => 'anthropic', 'api_key' => '%env(ANTHROPIC_API_KEY)%']);

        self::assertSame(['anthropic' => ['api_key' => 'sk-from-env']], $platformConfig->toAiPlatformConfig());
    }

    public function test_it_resolves_a_keyless_endpoint_provider(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['provider' => 'ollama', 'endpoint' => 'http://localhost:11434']);

        self::assertSame(['ollama' => ['endpoint' => 'http://localhost:11434']], $platformConfig->toAiPlatformConfig());
    }

    public function test_it_rejects_a_config_without_a_provider(): void
    {
        $this->expectException(MissingProviderException::class);

        (new StandalonePlatformConfigResolver())->resolve(['api_key' => 'sk-literal']);
    }

    public function test_it_rejects_an_empty_provider(): void
    {
        $this->expectException(MissingProviderException::class);

        (new StandalonePlatformConfigResolver())->resolve(['provider' => '', 'api_key' => 'sk-literal']);
    }

    public function test_it_rejects_an_env_placeholder_whose_variable_is_unset(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);

        (new StandalonePlatformConfigResolver())
            ->resolve(['provider' => 'anthropic', 'api_key' => '%env(ANTHROPIC_API_KEY)%']);
    }
}
