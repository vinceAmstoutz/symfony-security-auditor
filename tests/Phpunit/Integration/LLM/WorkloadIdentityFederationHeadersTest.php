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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Bridge\Anthropic\Factory;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\StreamingPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\FederatedAccessTokens;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\GithubActionsIdentityToken;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityFederation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityHttpClient;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\FederatedAnthropicAccess;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedTokenEstimator;

final class WorkloadIdentityFederationHeadersTest extends TestCase
{
    private const string MODEL = 'claude-opus-5-5';

    private const string IDENTITY_TOKEN_URL = 'https://pipelines.example/idtoken?api-version=2.0';

    private const string MESSAGES_URL = 'https://api.anthropic.com/v1/messages';

    private const string TOKEN_URL = 'https://api.anthropic.com/v1/oauth/token';

    /** @var array<string, array<array-key, mixed>> */
    private array $sentHeaders = [];

    /**
     * @return iterable<string, array{bool}>
     */
    public static function callModes(): iterable
    {
        yield 'streamed' => [true];
        yield 'buffered' => [false];
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    #[DataProvider('callModes')]
    public function test_a_call_through_the_anthropic_bridge_sends_the_federated_token_with_the_oauth_beta(bool $streamed): void
    {
        $platform = $this->federatedPlatform();

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($streamed ? new StreamingPlatform($platform) : $platform, self::MODEL, new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(1000), servingPlatform: 'anthropic', streaming: $streamed),
            new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        ))->complete('system', 'user');

        self::assertSame(
            [
                'answer' => '[]',
                self::IDENTITY_TOKEN_URL => ['authorization' => ['Authorization: Bearer request-token']],
                self::TOKEN_URL => ['anthropic-beta' => ['anthropic-beta: oauth-2025-04-20,oidc-federation-2026-04-01']],
                self::MESSAGES_URL => ['anthropic-beta' => ['anthropic-beta: oauth-2025-04-20'], 'authorization' => ['authorization: Bearer sk-ant-oat01-federated']],
            ],
            ['answer' => $llmResponse->content(), ...$this->sentHeaders],
        );
    }

    public function test_a_call_with_a_beta_of_the_bridge_asks_for_it_and_the_oauth_beta(): void
    {
        $this->federatedPlatform()->invoke(
            self::MODEL,
            new MessageBag(Message::ofUser('user')),
            ['max_tokens' => 2000, 'thinking' => ['type' => 'enabled', 'budget_tokens' => 1024]],
        )->getResult();

        self::assertSame(
            ['anthropic-beta' => ['anthropic-beta: interleaved-thinking-2025-05-14,oauth-2025-04-20'], 'authorization' => ['authorization: Bearer sk-ant-oat01-federated']],
            $this->sentHeaders[self::MESSAGES_URL] ?? null,
        );
    }

    private function federatedPlatform(): PlatformInterface
    {
        $mockHttpClient = new MockHttpClient(function (string $method, string $url, array $options): MockResponse {
            $this->record($url, $options);

            return match ($url) {
                self::IDENTITY_TOKEN_URL.'&audience=https://api.anthropic.com' => new MockResponse('{"value":"github-oidc-jwt"}'),
                self::TOKEN_URL => new MockResponse('{"access_token":"sk-ant-oat01-federated","expires_in":3600}'),
                default => $this->answerFor($options),
            };
        });

        return Factory::createPlatform(FederatedAnthropicAccess::API_KEY_PLACEHOLDER, new WorkloadIdentityHttpClient($mockHttpClient, new FederatedAccessTokens(
            $mockHttpClient,
            new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'),
            new GithubActionsIdentityToken($mockHttpClient, self::IDENTITY_TOKEN_URL, 'request-token'),
            new MockClock(),
        )));
    }

    /**
     * @param array<array-key, mixed> $options
     */
    private function record(string $url, array $options): void
    {
        $normalizedHeaders = $options['normalized_headers'];
        self::assertIsArray($normalizedHeaders);
        $sent = array_intersect_key($normalizedHeaders, ['anthropic-beta' => true, 'authorization' => true, 'x-api-key' => true]);
        ksort($sent);

        $this->sentHeaders[explode('&', $url)[0]] = $sent;
    }

    /**
     * @param array<array-key, mixed> $options
     */
    private function answerFor(array $options): MockResponse
    {
        self::assertIsString($options['body']);
        if (str_contains($options['body'], '"stream":true')) {
            return new MockResponse(implode('', array_map(
                static fn (array $event): string => \sprintf("event: %s\ndata: %s\n\n", $event['type'], json_encode($event, \JSON_THROW_ON_ERROR)),
                [
                    ['type' => 'message_start', 'message' => ['id' => 'msg_1', 'type' => 'message', 'role' => 'assistant', 'model' => self::MODEL, 'content' => [], 'stop_reason' => null, 'usage' => ['input_tokens' => 10, 'output_tokens' => 1]]],
                    ['type' => 'content_block_start', 'index' => 0, 'content_block' => ['type' => 'text', 'text' => '']],
                    ['type' => 'content_block_delta', 'index' => 0, 'delta' => ['type' => 'text_delta', 'text' => '[]']],
                    ['type' => 'content_block_stop', 'index' => 0],
                    ['type' => 'message_delta', 'delta' => ['stop_reason' => 'end_turn', 'stop_sequence' => null], 'usage' => ['output_tokens' => 2]],
                    ['type' => 'message_stop'],
                ],
            )), ['response_headers' => ['content-type' => 'text/event-stream']]);
        }

        return new MockResponse(
            json_encode(['id' => 'msg_1', 'type' => 'message', 'role' => 'assistant', 'model' => self::MODEL, 'content' => [['type' => 'text', 'text' => '[]']], 'stop_reason' => 'end_turn', 'usage' => ['input_tokens' => 10, 'output_tokens' => 2]], \JSON_THROW_ON_ERROR),
            ['response_headers' => ['content-type' => 'application/json']],
        );
    }
}
