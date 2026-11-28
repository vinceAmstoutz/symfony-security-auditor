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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Standalone;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\FederatedAnthropicAccess;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;

final class FederatedAnthropicAccessTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

    private const array FEDERATION = [
        'ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule',
        'ANTHROPIC_ORGANIZATION_ID' => 'org-uuid',
        'ACTIONS_ID_TOKEN_REQUEST_URL' => 'https://pipelines.actions.githubusercontent.com/abc/idtoken?api-version=2.0',
        'ACTIONS_ID_TOKEN_REQUEST_TOKEN' => 'request-token',
    ];

    public function test_an_api_key_wins_over_federation_as_in_the_anthropic_sdk(): void
    {
        self::assertNull(FederatedAnthropicAccess::fromEnvironment([...self::FEDERATION, 'ANTHROPIC_API_KEY' => 'sk-ant-api03-stored']));
    }

    public function test_only_the_anthropic_block_reads_a_placeholder_api_key_that_federation_replaces(): void
    {
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment(self::FEDERATION);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        self::assertSame(
            ['anthropic' => ['ANTHROPIC_API_KEY' => FederatedAnthropicAccess::API_KEY_PLACEHOLDER]],
            $federatedAnthropicAccess->platformEnvironments(),
        );
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_the_anthropic_platform_sends_its_requests_with_a_federated_bearer_token(): void
    {
        $messagesRequest = new MockResponse('{}');
        $containerBuilder = new ContainerBuilder();
        $containerBuilder->register('http_client', HttpClientInterface::class)->setSynthetic(true);
        $containerBuilder->set('http_client', new MockHttpClient([
            new MockResponse('{"value":"github-oidc-jwt"}'),
            new MockResponse('{"access_token":"sk-ant-oat01-federated","expires_in":599}'),
            $messagesRequest,
        ]));
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment(self::FEDERATION);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        $aiConfig = $federatedAnthropicAccess->configure(new StandalonePlatformConfig(['anthropic' => ['api_key' => FederatedAnthropicAccess::API_KEY_PLACEHOLDER]]), $containerBuilder);
        $anthropic = $aiConfig['platform']['anthropic'];
        self::assertIsArray($anthropic);
        self::assertIsString($anthropic['http_client'] ?? null);
        $httpClient = $containerBuilder->get($anthropic['http_client']);
        self::assertInstanceOf(HttpClientInterface::class, $httpClient);
        $httpClient->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['x-api-key' => FederatedAnthropicAccess::API_KEY_PLACEHOLDER]]);

        $normalizedHeaders = $messagesRequest->getRequestOptions()['normalized_headers'];
        self::assertIsArray($normalizedHeaders);
        self::assertSame([['authorization: Bearer sk-ant-oat01-federated'], null], [$normalizedHeaders['authorization'] ?? null, $normalizedHeaders['x-api-key'] ?? null]);
    }

    /**
     * @param array<string, string> $environment
     *
     * @throws UnobtainableIdentityTokenException
     */
    #[DataProvider('environmentsWithoutAnIdentityTokenRequest')]
    public function test_federation_outside_a_job_that_can_request_an_identity_token_names_the_permission(array $environment): void
    {
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment($environment);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        $this->expectException(UnobtainableIdentityTokenException::class);
        $this->expectExceptionMessageContaining('Workload identity federation reads the identity token from GitHub Actions: run in a job with the "id-token: write" permission, or set ANTHROPIC_API_KEY.');

        $federatedAnthropicAccess->configure(new StandalonePlatformConfig(['anthropic' => ['api_key' => FederatedAnthropicAccess::API_KEY_PLACEHOLDER]]), new ContainerBuilder());
    }

    /**
     * @param array<string, string> $environment
     */
    #[DataProvider('environmentsWithoutAnIdentityTokenRequest')]
    public function test_it_says_why_a_job_that_cannot_request_an_identity_token_cannot_sign_in(array $environment): void
    {
        self::assertSame(
            'Workload identity federation reads the identity token from GitHub Actions: run in a job with the "id-token: write" permission, or set ANTHROPIC_API_KEY.',
            FederatedAnthropicAccess::fromEnvironment($environment)?->identityTokenRefusal()?->getMessage(),
        );
    }

    public function test_a_job_that_can_request_an_identity_token_is_not_refused(): void
    {
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment(self::FEDERATION);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        self::assertNull($federatedAnthropicAccess->identityTokenRefusal());
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function environmentsWithoutAnIdentityTokenRequest(): iterable
    {
        $rule = ['ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule', 'ANTHROPIC_ORGANIZATION_ID' => 'org-uuid'];

        yield 'neither the request URL nor its token' => [$rule];
        yield 'no request token' => [[...$rule, 'ACTIONS_ID_TOKEN_REQUEST_URL' => 'https://pipelines.actions.githubusercontent.com/abc/idtoken']];
        yield 'no request URL' => [[...$rule, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' => 'request-token']];
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_config_without_the_anthropic_platform_is_left_as_it_is(): void
    {
        $containerBuilder = new ContainerBuilder();
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment(['ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule', 'ANTHROPIC_ORGANIZATION_ID' => 'org-uuid']);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        $platform = ['openai' => ['api_key' => 'sk-proj-key']];

        self::assertSame(
            [['platform' => $platform], false],
            [$federatedAnthropicAccess->configure(new StandalonePlatformConfig($platform), $containerBuilder), $containerBuilder->hasDefinition(FederatedAnthropicAccess::HTTP_CLIENT_SERVICE)],
        );
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    #[DataProvider('anthropicBlocksTheRunDoesNotCall')]
    public function test_an_anthropic_block_the_run_does_not_call_is_left_as_it_is_outside_github_actions(?string $provider): void
    {
        $containerBuilder = new ContainerBuilder();
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment(['ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule', 'ANTHROPIC_ORGANIZATION_ID' => 'org-uuid']);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        $platform = ['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL], 'openai' => ['api_key' => 'sk-proj-key']];

        self::assertSame(
            [['platform' => $platform], false],
            [$federatedAnthropicAccess->configure(new StandalonePlatformConfig($platform, $provider), $containerBuilder), $containerBuilder->hasDefinition(FederatedAnthropicAccess::HTTP_CLIENT_SERVICE)],
        );
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function anthropicBlocksTheRunDoesNotCall(): iterable
    {
        yield 'another platform the provider selects' => ['openai'];
        yield 'no provider among several platforms' => [null];
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_keeps_the_other_platforms_and_the_other_anthropic_settings(): void
    {
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment(self::FEDERATION);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        self::assertSame(
            ['platform' => [
                'openai' => ['api_key' => 'sk-proj-key'],
                'anthropic' => ['api_key' => FederatedAnthropicAccess::API_KEY_PLACEHOLDER, 'cache_retention' => 'long', 'http_client' => FederatedAnthropicAccess::HTTP_CLIENT_SERVICE],
            ]],
            $federatedAnthropicAccess->configure(
                new StandalonePlatformConfig(['openai' => ['api_key' => 'sk-proj-key'], 'anthropic' => ['api_key' => FederatedAnthropicAccess::API_KEY_PLACEHOLDER, 'cache_retention' => 'long']], 'anthropic'),
                new ContainerBuilder(),
            ),
        );
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_federation_setting_holding_percent_signs_reaches_the_exchange_as_written(): void
    {
        $exchange = new MockResponse('{"access_token":"sk-ant-oat01-federated","expires_in":599}');
        $containerBuilder = new ContainerBuilder();
        $containerBuilder->register('http_client', HttpClientInterface::class)->setSynthetic(true);
        $containerBuilder->set('http_client', new MockHttpClient([new MockResponse('{"value":"github-oidc-jwt"}'), $exchange, new MockResponse('{}')]));
        $federatedAnthropicAccess = FederatedAnthropicAccess::fromEnvironment([...self::FEDERATION, 'ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_%kernel.debug%']);
        self::assertInstanceOf(FederatedAnthropicAccess::class, $federatedAnthropicAccess);

        $federatedAnthropicAccess->configure(new StandalonePlatformConfig(['anthropic' => ['api_key' => FederatedAnthropicAccess::API_KEY_PLACEHOLDER]]), $containerBuilder);
        $httpClient = $containerBuilder->get(FederatedAnthropicAccess::HTTP_CLIENT_SERVICE);
        self::assertInstanceOf(HttpClientInterface::class, $httpClient);
        $httpClient->request('POST', 'https://api.anthropic.com/v1/messages');

        $body = $exchange->getRequestOptions()['body'] ?? null;
        self::assertIsString($body);
        self::assertStringContainsString('"federation_rule_id":"fdrl_%kernel.debug%"', $body);
    }
}
