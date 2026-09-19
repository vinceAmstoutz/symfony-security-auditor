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
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommandInput;
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
    public function test_it_names_the_refusal_that_leaves_the_user_somewhere_to_go(string $provider, InitCommandInput $initCommandInput, string $expected): void
    {
        self::assertStringContainsString(
            $expected,
            (string) InitRefusal::forProvider(ProviderKey::of($provider), $provider, $initCommandInput, self::CONFIG_FILE),
        );
    }

    /**
     * @return iterable<string, array{string, InitCommandInput, string}>
     */
    public static function competingRefusalCases(): iterable
    {
        yield 'a platform init cannot write is named before its missing instance' => ['azure', self::input(), 'needs a "deployment" name'];
        yield 'a platform init cannot write is named before a stray base url' => ['bedrock', self::input(baseUrl: 'https://gw.example'), 'bedrock_runtime_client'];
        yield 'a missing platform is named before a stray base url' => ['.gateway', self::input(baseUrl: 'https://gw.example'), 'names no platform before the dot'];
        yield 'a stray instance is named before a stray base url' => ['ollama.x', self::input(baseUrl: 'https://gw.example'), 'takes a single connection block'];
        yield 'a missing instance is named before a stray base url' => ['generic', self::input(baseUrl: 'https://gw.example'), 'is configured per instance'];
        yield 'a stray base url is named when nothing else is wrong' => ['anthropic', self::input(baseUrl: 'https://gw.example'), '--base-url applies to the platforms that expose one'];
        yield 'a stray endpoint is named when nothing else is wrong' => ['anthropic', self::input(endpoint: 'http://localhost:11434'), '--endpoint applies to the platforms that declare one'];
        yield 'a platform naming its endpoint base_url is pointed at the option it does take' => ['albert', self::input(endpoint: 'http://localhost:11434'), 'use --base-url'];
        yield 'a stray base url is named before a stray endpoint' => ['anthropic', self::input(baseUrl: 'https://gw.example', endpoint: 'http://localhost:11434'), '--base-url applies'];
        yield 'an omitted key the platform requires is named when nothing else is wrong' => ['anthropic', self::input(noApiKey: true), '--no-api-key applies to the platforms whose key is optional'];
        yield 'a stray endpoint is named before an omitted key' => ['anthropic', self::input(endpoint: 'http://localhost:11434', noApiKey: true), '--endpoint applies'];
        yield 'asking for no key while naming the variable to read it from is a contradiction' => ['ollama', self::input(noApiKey: true, envVar: 'OLLAMA_API_KEY'), 'contradict each other'];
        yield 'the contradiction is named before the platform is consulted' => ['anthropic', self::input(noApiKey: true, envVar: 'ANTHROPIC_API_KEY'), 'contradict each other'];
        yield 'a stray endpoint is named before the contradiction it sits beside' => ['anthropic', self::input(endpoint: 'http://localhost:11434', noApiKey: true, envVar: 'ANTHROPIC_API_KEY'), '--endpoint applies'];
    }

    #[DataProvider('writableCases')]
    public function test_it_finds_nothing_wrong_with_a_provider_init_can_write(string $provider, InitCommandInput $initCommandInput): void
    {
        self::assertNull(InitRefusal::forProvider(ProviderKey::of($provider), $provider, $initCommandInput, self::CONFIG_FILE));
    }

    /**
     * @return iterable<string, array{string, InitCommandInput}>
     */
    public static function writableCases(): iterable
    {
        yield 'an instance-keyed platform with the base url it exposes' => ['generic.my_gateway', self::input(baseUrl: 'https://gw.example')];
        yield 'a platform with the endpoint it declares' => ['ollama', self::input(endpoint: 'http://localhost:11434')];
        yield 'a platform whose key the bundle leaves optional, asked for none' => ['ollama', self::input(endpoint: 'http://localhost:11434', noApiKey: true)];
    }

    #[DataProvider('resolvedEndpointCases')]
    public function test_it_reports_what_is_wrong_with_the_endpoint_it_resolved(string $provider, ?string $endpoint, ?string $expected): void
    {
        $refusal = InitRefusal::forResolvedEndpoint(ProviderKey::of($provider), $provider, $endpoint);

        null === $expected
            ? self::assertNull($refusal)
            : self::assertStringContainsString($expected, (string) $refusal);
    }

    /**
     * @return iterable<string, array{string, string|null, string|null}>
     */
    public static function resolvedEndpointCases(): iterable
    {
        yield 'the platform declaring no default is refused without one' => ['ollama', null, 'declares no default endpoint'];
        yield 'a platform carrying a default keeps it' => ['deepgram', null, null];
        yield 'a platform taking no endpoint at all is left alone' => ['anthropic', null, null];
        yield 'a container parameter would not survive compilation' => ['ollama', 'http://%host%:11434', 'read as a container parameter'];
        yield 'an env placeholder is the documented way to defer it' => ['ollama', '%env(OLLAMA_ENDPOINT)%', null];
        yield 'a plain origin is accepted' => ['ollama', 'http://localhost:11434', null];
    }

    private static function input(?string $baseUrl = null, ?string $endpoint = null, bool $noApiKey = false, ?string $envVar = null): InitCommandInput
    {
        $initCommandInput = new InitCommandInput();
        $initCommandInput->baseUrl = $baseUrl;
        $initCommandInput->endpoint = $endpoint;
        $initCommandInput->noApiKey = $noApiKey;
        $initCommandInput->envVar = $envVar;

        return $initCommandInput;
    }
}
