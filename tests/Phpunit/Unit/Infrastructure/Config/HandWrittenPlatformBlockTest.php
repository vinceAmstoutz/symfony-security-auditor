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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatformBlock;

final class HandWrittenPlatformBlockTest extends TestCase
{
    /**
     * @param array<string, mixed> $expected
     */
    #[DataProvider('blockCases')]
    public function test_it_drafts_the_configuration_to_complete_by_hand(string $provider, array $expected): void
    {
        self::assertSame($expected, HandWrittenPlatformBlock::for(ProviderKey::of($provider), 'our-model'));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function blockCases(): iterable
    {
        yield 'a flat platform holds its connection directly' => [
            'lmstudio',
            ['provider' => 'lmstudio', 'platform' => ['lmstudio' => ['host_url' => 'http://127.0.0.1:1234']], 'model' => 'our-model'],
        ];

        yield 'an instance-keyed platform keeps the instance it was given' => [
            'azure.prod',
            [
                'provider' => 'azure.prod',
                'platform' => ['azure' => ['prod' => ['base_url' => 'https://<resource>.openai.azure.com', 'deployment' => '<deployment>', 'api_version' => '<api version>', 'api_key' => '%env(AZURE_API_KEY)%']]],
                'model' => 'our-model',
            ],
        ];

        yield 'an instance-keyed platform named without one gets a default instance' => [
            'azure',
            [
                'provider' => 'azure.default',
                'platform' => ['azure' => ['default' => ['base_url' => 'https://<resource>.openai.azure.com', 'deployment' => '<deployment>', 'api_version' => '<api version>', 'api_key' => '%env(AZURE_API_KEY)%']]],
                'model' => 'our-model',
            ],
        ];

        yield 'a platform taking no settings at all gets an empty block' => [
            'transformersphp',
            ['provider' => 'transformersphp', 'platform' => ['transformersphp' => []], 'model' => 'our-model'],
        ];
    }
}
