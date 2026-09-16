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
    /**
     * @param array<string, mixed> $expected
     */
    #[DataProvider('configCases')]
    public function test_it_builds_the_rootless_config(string $provider, ?string $baseUrl, array $expected): void
    {
        self::assertSame(
            $expected,
            (new StandaloneConfigFactory())->create($provider, 'gpt-5.4', 'API_TOKEN', $baseUrl),
        );
    }

    /**
     * @return iterable<string, array{string, string|null, array<string, mixed>}>
     */
    public static function configCases(): iterable
    {
        yield 'a flat platform holds the connection directly' => [
            'openai',
            null,
            [
                'provider' => 'openai',
                'platform' => ['openai' => ['api_key' => '%env(API_TOKEN)%']],
                'model' => 'gpt-5.4',
            ],
        ];

        yield 'an instance-keyed platform nests it under the instance' => [
            'openresponses.my_gateway',
            'https://gw.example',
            [
                'provider' => 'openresponses.my_gateway',
                'platform' => ['openresponses' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(API_TOKEN)%']]],
                'model' => 'gpt-5.4',
            ],
        ];

        yield 'an instance-keyed platform keeps the nesting without a base url' => [
            'generic.my_gateway',
            null,
            [
                'provider' => 'generic.my_gateway',
                'platform' => ['generic' => ['my_gateway' => ['api_key' => '%env(API_TOKEN)%']]],
                'model' => 'gpt-5.4',
            ],
        ];
    }
}
