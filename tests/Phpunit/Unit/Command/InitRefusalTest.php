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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitRefusal;

final class InitRefusalTest extends TestCase
{
    private const string CONFIG_FILE = '/home/you/.config/symfony-security-auditor/config.yaml';

    /**
     * Each case pairs a provider that breaks two rules at once with the rule
     * the user should hear about, so a reordering that sends someone into a
     * second refusal fails here rather than in a support thread.
     */
    #[DataProvider('competingRefusalCases')]
    public function test_it_names_the_refusal_that_leaves_the_user_somewhere_to_go(string $provider, ?string $baseUrl, string $expected): void
    {
        self::assertStringContainsString(
            $expected,
            (string) InitRefusal::forProvider(ProviderKey::of($provider), $provider, $baseUrl, self::CONFIG_FILE),
        );
    }

    /**
     * @return iterable<string, array{string, string|null, string}>
     */
    public static function competingRefusalCases(): iterable
    {
        yield 'a platform init cannot write is named before its missing instance' => ['azure', null, 'needs a "deployment" name'];
        yield 'a platform init cannot write is named before a stray base url' => ['bedrock', 'https://gw.example', 'bedrock_runtime_client'];
        yield 'a missing platform is named before a stray base url' => ['.gateway', 'https://gw.example', 'names no platform before the dot'];
        yield 'a stray instance is named before a stray base url' => ['ollama.x', 'https://gw.example', 'takes a single connection block'];
        yield 'a missing instance is named before a stray base url' => ['generic', 'https://gw.example', 'is configured per instance'];
        yield 'a stray base url is named when nothing else is wrong' => ['anthropic', 'https://gw.example', '--base-url applies to the platforms that expose one'];
    }

    public function test_it_finds_nothing_wrong_with_a_provider_init_can_write(): void
    {
        self::assertNull(InitRefusal::forProvider(ProviderKey::of('generic.my_gateway'), 'generic.my_gateway', 'https://gw.example', self::CONFIG_FILE));
    }
}
