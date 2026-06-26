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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;

final class StandalonePlatformConfigResolverTest extends TestCase
{
    public function test_it_passes_the_platform_block_through_untouched(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => 'sk-literal']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-literal']]], $platformConfig->toAiConfig());
    }

    public function test_it_resolves_env_placeholders_anywhere_in_the_platform_block(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY' => 'sk-from-env']))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-from-env']]], $platformConfig->toAiConfig());
    }

    public function test_it_resolves_placeholders_in_a_nested_generic_platform(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver(['LLM_BASE_URL' => 'http://localhost:1234']))
            ->resolve(['platform' => ['generic' => ['default' => ['base_url' => '%env(LLM_BASE_URL)%', 'supports_completions' => true]]]]);

        self::assertSame(
            ['platform' => ['generic' => ['default' => ['base_url' => 'http://localhost:1234', 'supports_completions' => true]]]],
            $platformConfig->toAiConfig(),
        );
    }

    public function test_it_carries_the_active_provider_selector(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver())->resolve([
            'provider' => 'openai',
            'platform' => ['anthropic' => ['api_key' => 'a'], 'openai' => ['api_key' => 'b']],
        ]);

        self::assertSame('openai', $platformConfig->activeProvider);
    }

    public function test_it_has_no_active_provider_when_the_selector_is_absent(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => 'a']]]);

        self::assertNull($platformConfig->activeProvider);
    }

    public function test_it_ignores_an_empty_active_provider_selector(): void
    {
        $platformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['provider' => '', 'platform' => ['anthropic' => ['api_key' => 'a']]]);

        self::assertNull($platformConfig->activeProvider);
    }

    public function test_it_rejects_a_config_without_a_platform_block(): void
    {
        $this->expectException(MissingPlatformException::class);

        (new StandalonePlatformConfigResolver())->resolve(['provider' => 'anthropic']);
    }

    public function test_it_rejects_an_empty_platform_block(): void
    {
        $this->expectException(MissingPlatformException::class);

        (new StandalonePlatformConfigResolver())->resolve(['platform' => []]);
    }

    public function test_it_rejects_an_env_placeholder_whose_variable_is_unset(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);

        (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]]);
    }
}
