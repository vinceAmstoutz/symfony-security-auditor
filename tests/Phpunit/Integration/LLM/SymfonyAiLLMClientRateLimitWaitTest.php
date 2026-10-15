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
use Symfony\AI\Platform\Exception\RateLimitExceededException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\BackoffSchedule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimitBackoff;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * A rate-limited provider may name more than one wait: OpenAI's bridge
 * hands back its request-window reset as the `Retry-After` hint, while the
 * answer to a request over the token limit says how long that limit needs
 * (`Please try again in 8.064s.`) and when the token window resets
 * (`x-ratelimit-reset-tokens`). The retry waits for the longest of them,
 * never less than it would without them, up to the rate-limit ceiling.
 */
final class SymfonyAiLLMClientRateLimitWaitTest extends TestCase
{
    private const string TPM_LIMIT_REACHED = 'Rate limit reached for gpt-4o in organization org-abc on tokens per min (TPM): Limit 30000, Used 28000, Requested 6000. Please try again in 8.064s. Visit https://platform.openai.com/account/rate-limits to learn more.';

    /**
     * @param array<string, list<string>> $headers
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('rateLimitWaitCases')]
    public function test_a_rate_limited_call_waits_for_the_longest_wait_the_provider_names(?int $retryAfter, string $message, array $headers, int $expectedWaitMs): void
    {
        $fakeSleeper = new FakeSleeper();
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->rateLimited($retryAfter, $message, $headers), $this->answer()]);

        $llmResponse = $this->client($scriptedDeferredPlatform, $fakeSleeper)->complete('sys', 'usr');

        self::assertSame('[]', $llmResponse->content());
        self::assertSame([$expectedWaitMs], $fakeSleeper->durations);
    }

    /**
     * @return iterable<string, array{?int, string, array<string, list<string>>, int}>
     */
    public static function rateLimitWaitCases(): iterable
    {
        yield 'the message asks longer than the request-window reset' => [1, self::TPM_LIMIT_REACHED, ['x-ratelimit-reset-requests' => ['1s'], 'x-ratelimit-reset-tokens' => ['7s']], 8_064];
        yield 'the token window resets later than the message asks' => [1, self::TPM_LIMIT_REACHED, ['x-ratelimit-reset-requests' => ['1s'], 'x-ratelimit-reset-tokens' => ['1m30s']], 90_000];
        yield 'the token window reset past the ceiling is held to it' => [1, self::TPM_LIMIT_REACHED, ['x-ratelimit-reset-requests' => ['1s'], 'x-ratelimit-reset-tokens' => ['6m0s']], 300_000];
        yield 'a retry-after longer than every other wait still decides' => [30, self::TPM_LIMIT_REACHED, ['x-ratelimit-reset-tokens' => ['8.064s']], 30_000];
        yield 'with no retry-after, the back-off longer than the message still decides' => [null, self::TPM_LIMIT_REACHED, ['x-ratelimit-reset-requests' => ['120ms'], 'x-ratelimit-reset-tokens' => ['8.064s']], 60_000];
        yield 'with no retry-after, a message asking longer than the back-off decides' => [null, 'Rate limit reached for gpt-4o on tokens per day (TPD). Please try again in 2m30s.', [], 150_000];
    }

    /**
     * @param array<string, list<string>> $headers
     */
    private function rateLimited(?int $retryAfter, string $message, array $headers): DeferredResult
    {
        $response = self::createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(429);
        $response->method('getHeaders')->willReturn($headers);

        return new DeferredResult(new ThrowingConverter(new RateLimitExceededException($retryAfter, $message)), new RawHttpResult($response), []);
    }

    private function answer(): DeferredResult
    {
        return new DeferredResult(new PlainConverter(new TextResult('[]')), new InMemoryRawResult(), []);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    private function client(ScriptedDeferredPlatform $scriptedDeferredPlatform, FakeSleeper $fakeSleeper): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedDeferredPlatform, 'gpt-4o', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(
                new RetryPolicy(new BackoffSchedule(maxAttempts: 3, jitterRatio: 0.0), new RateLimitBackoff(initialDelayMs: 60_000, maxDelayMs: 300_000)),
                sleeper: $fakeSleeper,
                rateLimiter: new FakeRateLimiter(),
            ),
        );
    }
}
