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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformApiKey;

final class PlatformApiKeyTest extends TestCase
{
    public function test_it_finds_the_key_a_provider_block_nests(): void
    {
        self::assertSame('anthropic-test-key-nested', PlatformApiKey::valueIn(['anthropic' => ['api_key' => 'anthropic-test-key-nested']]));
    }

    public function test_it_finds_the_key_whichever_provider_holds_it(): void
    {
        self::assertSame('openai-test-key-value', PlatformApiKey::valueIn(['ollama' => ['host_url' => 'http://localhost:11434'], 'openai' => ['api_key' => 'openai-test-key-value']]));
    }

    /**
     * @param array<array-key, mixed> $platform
     */
    #[DataProvider('platformsWithoutAnApiKey')]
    public function test_it_finds_no_key_where_none_is_configured(array $platform): void
    {
        self::assertNull(PlatformApiKey::valueIn($platform));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function platformsWithoutAnApiKey(): iterable
    {
        yield 'a local provider that needs none' => [['ollama' => ['host_url' => 'http://localhost:11434']]];
        yield 'an empty platform block' => [[]];
        yield 'a blank key' => [['anthropic' => ['api_key' => '']]];
        yield 'a key that is not a string' => [['anthropic' => ['api_key' => ['nested']]]];
    }
}
