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

    public function test_it_names_the_one_setting_that_is_a_credential(): void
    {
        self::assertTrue(PlatformApiKey::names('api_key'));
    }

    #[DataProvider('settingsThatAreNoCredential')]
    public function test_it_names_no_other_setting_a_credential(int|string $key): void
    {
        self::assertFalse(PlatformApiKey::names($key));
    }

    /**
     * @return iterable<string, array{int|string}>
     */
    public static function settingsThatAreNoCredential(): iterable
    {
        yield 'a connection setting' => ['base_url'];
        yield 'a platform name' => ['anthropic'];
        yield 'a list index' => [0];
    }

    public function test_it_finds_the_key_of_the_provider_the_configuration_selects(): void
    {
        $platform = ['anthropic' => ['api_key' => 'anthropic-test-key-value'], 'openai' => ['api_key' => 'openai-test-key-value']];

        self::assertSame('openai-test-key-value', PlatformApiKey::valueForProvider($platform, 'openai'));
    }

    public function test_it_finds_the_key_of_the_selected_instance(): void
    {
        $platform = ['generic' => ['default' => ['api_key' => 'generic-test-key-default'], 'gateway' => ['api_key' => 'generic-test-key-gateway']]];

        self::assertSame('generic-test-key-gateway', PlatformApiKey::valueForProvider($platform, 'generic.gateway'));
    }

    public function test_it_searches_the_whole_block_when_no_provider_is_selected(): void
    {
        self::assertSame('anthropic-test-key-value', PlatformApiKey::valueForProvider(['anthropic' => ['api_key' => 'anthropic-test-key-value']], null));
    }

    public function test_it_finds_no_key_for_a_selected_provider_that_is_not_configured(): void
    {
        self::assertNull(PlatformApiKey::valueForProvider(['anthropic' => ['api_key' => 'anthropic-test-key-value']], 'mistral'));
    }

    public function test_it_finds_no_key_for_a_selected_instance_that_is_not_configured(): void
    {
        self::assertNull(PlatformApiKey::valueForProvider(['generic' => ['default' => ['api_key' => 'generic-test-key-default']]], 'generic.gateway'));
    }
}
