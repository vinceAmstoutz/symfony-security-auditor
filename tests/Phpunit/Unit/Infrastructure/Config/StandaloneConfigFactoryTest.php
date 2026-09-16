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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;

final class StandaloneConfigFactoryTest extends TestCase
{
    public function test_it_builds_the_rootless_config_with_an_env_referenced_api_key(): void
    {
        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            (new StandaloneConfigFactory())->create('openai', 'gpt-5.4', 'OPENAI_API_KEY'),
        );
    }

    public function test_it_nests_the_connection_under_its_instance_for_an_instance_keyed_platform(): void
    {
        self::assertSame(
            [
                'provider' => 'generic.my_gateway',
                'platform' => ['generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(GATEWAY_TOKEN)%']]],
                'model' => 'our-model',
            ],
            (new StandaloneConfigFactory())->create('generic.my_gateway', 'our-model', 'GATEWAY_TOKEN', 'https://gw.example'),
        );
    }

    public function test_it_keeps_an_instance_keyed_platform_nested_even_when_it_exposes_no_base_url(): void
    {
        self::assertSame(
            [
                'provider' => 'bedrock.default',
                'platform' => ['bedrock' => ['default' => ['api_key' => '%env(AWS_TOKEN)%']]],
                'model' => 'our-model',
            ],
            (new StandaloneConfigFactory())->create('bedrock.default', 'our-model', 'AWS_TOKEN'),
        );
    }

    public function test_it_accepts_a_base_url_for_a_flat_platform_too(): void
    {
        self::assertSame(
            [
                'provider' => 'ollama',
                'platform' => ['ollama' => ['base_url' => 'http://localhost:11434', 'api_key' => '%env(OLLAMA_TOKEN)%']],
                'model' => 'llama3.3',
            ],
            (new StandaloneConfigFactory())->create('ollama', 'llama3.3', 'OLLAMA_TOKEN', 'http://localhost:11434'),
        );
    }

    #[DataProvider('omittedBaseUrlCases')]
    public function test_it_omits_the_base_url_when_none_was_supplied(?string $baseUrl): void
    {
        self::assertSame(
            [
                'provider' => 'generic.gw',
                'platform' => ['generic' => ['gw' => ['api_key' => '%env(TOKEN)%']]],
                'model' => 'our-model',
            ],
            (new StandaloneConfigFactory())->create('generic.gw', 'our-model', 'TOKEN', $baseUrl),
        );
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function omittedBaseUrlCases(): iterable
    {
        yield 'no base url given' => [null];
        yield 'an empty answer at the base url prompt' => [''];
    }
}
