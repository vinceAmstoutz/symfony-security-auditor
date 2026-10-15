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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\AI\Platform\Exception\RuntimeException as PlatformRuntimeException;
use Symfony\AI\Platform\Exception\ServerException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\StructuredVulnerabilityCollectionSession;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * A provider failing a request with an HTTP status that clears on its own —
 * a timeout, a rate limit, a server error — served nothing, so the request is
 * retried with the usual back-off and booked as nothing, whatever the bridge
 * made of the body that came with the status: the Ollama bridge reads any
 * error body as `Response does not contain message.`, and a proxy's HTML page
 * as a JSON syntax error.
 */
final class SymfonyAiLLMClientTransientStatusTest extends TestCase
{
    private const string OLLAMA_EMPTY_ANSWER = 'Response does not contain message.';

    private const string PROXY_HTML_PAGE = 'Syntax error for "http://127.0.0.1:11434/api/chat".';

    private BudgetTracker $budgetTracker;

    private FakeRateLimiter $fakeRateLimiter;

    private FakeSleeper $fakeSleeper;

    /**
     * @throws InvalidAuditBudgetException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->budgetTracker = new BudgetTracker(AuditBudget::forTokens(1_000_000), new CostCalculator($this->freePricing()));
        $this->fakeRateLimiter = new FakeRateLimiter();
        $this->fakeSleeper = new FakeSleeper();
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('statusesThatClearOnTheirOwnCases')]
    public function test_complete_retries_a_status_that_clears_on_its_own_and_books_nothing_for_it(int $status, string $bridgeMessage, int $expectedBackOffMs): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->failedWithStatus($status, $bridgeMessage), $this->answer()]);

        $llmResponse = $this->client($scriptedDeferredPlatform)->complete('sys', 'user');

        self::assertSame('[]', $llmResponse->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
        self::assertSame([$expectedBackOffMs], $this->fakeSleeper->durations);
        self::assertSame(25, $this->budgetTracker->tokensUsed());
        self::assertSame([0, 0], $this->fakeRateLimiter->recorded[0]);
    }

    /**
     * @return iterable<string, array{int, string, int}>
     */
    public static function statusesThatClearOnTheirOwnCases(): iterable
    {
        yield 'Ollama answering a request timeout' => [408, self::OLLAMA_EMPTY_ANSWER, 500];
        yield 'Ollama answering a request that came too early' => [425, self::OLLAMA_EMPTY_ANSWER, 500];
        yield 'Ollama Cloud answering a rate limit, which waits for the rate-limit back-off' => [429, self::OLLAMA_EMPTY_ANSWER, 66_000];
        yield 'Ollama answering a runner crash' => [500, self::OLLAMA_EMPTY_ANSWER, 500];
        yield 'a proxy answering a bad gateway page' => [502, self::PROXY_HTML_PAGE, 500];
        yield 'Ollama answering it is busy' => [503, self::OLLAMA_EMPTY_ANSWER, 500];
        yield 'a proxy answering a gateway timeout page' => [504, self::PROXY_HTML_PAGE, 500];
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_with_tools_retries_a_status_that_clears_on_its_own(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->failedWithStatus(503, self::OLLAMA_EMPTY_ANSWER), $this->answer()]);

        $llmResponse = $this->client($scriptedDeferredPlatform)->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('[]', $llmResponse->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_retries_a_status_that_clears_on_its_own(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->failedWithStatus(503, self::OLLAMA_EMPTY_ANSWER), $this->answer()]);

        $llmResponses = $this->client($scriptedDeferredPlatform)->completeBatch([['system' => 'sys', 'user' => 'user']], 2);

        self::assertSame('[]', $llmResponses[0]->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_retries_a_status_that_clears_on_its_own(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->failedWithStatus(503, self::OLLAMA_EMPTY_ANSWER), $this->answer()]);

        $llmResponses = $this->client($scriptedDeferredPlatform)->completeBatchWithTools([['system' => 'sys', 'user' => 'user', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('[]', $llmResponses[0]->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('statusesTheBridgeReadsAsAnEmptyAnswerCases')]
    public function test_complete_reads_a_status_still_failing_once_the_retries_are_spent_as_the_bridge_reads_it(int $status): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform($this->alwaysFailingWithStatus($status, self::OLLAMA_EMPTY_ANSWER));

        $llmResponse = $this->client($scriptedDeferredPlatform)->complete('sys', 'user');

        self::assertSame('empty_content', $llmResponse->stopReason());
        self::assertSame(3, $scriptedDeferredPlatform->invocations);
        self::assertSame([[0, 0], [0, 0], [$this->fakeRateLimiter->acquired[2], 0]], $this->fakeRateLimiter->recorded);
        self::assertSame($this->fakeRateLimiter->acquired[2], $this->budgetTracker->tokensUsed());
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function statusesTheBridgeReadsAsAnEmptyAnswerCases(): iterable
    {
        yield 'a request timeout' => [408];
        yield 'a request that came too early' => [425];
        yield 'a rate limit' => [429];
        yield 'a runner crash' => [500];
        yield 'a busy server' => [503];
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     */
    public function test_complete_still_aborts_on_a_proxy_page_still_failing_once_the_retries_are_spent(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform($this->alwaysFailingWithStatus(502, self::PROXY_HTML_PAGE));

        $aborted = null;
        try {
            $this->client($scriptedDeferredPlatform)->complete('sys', 'user');
        } catch (NonTransientLLMFailureException $nonTransientLLMFailureException) {
            $aborted = $nonTransientLLMFailureException->getMessage();
        }

        self::assertSame('LLM call failed with non-transient error: '.self::PROXY_HTML_PAGE, $aborted);
        self::assertSame(3, $scriptedDeferredPlatform->invocations);
        self::assertSame(0, $this->budgetTracker->tokensUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_still_aborts_on_a_server_error_the_bridge_reported_itself_once_the_retries_are_spent(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            $this->failedWithStatusAs(503, new ServerException(503, 'Service Unavailable')),
            $this->failedWithStatusAs(503, new ServerException(503, 'Service Unavailable')),
            $this->failedWithStatusAs(503, new ServerException(503, 'Service Unavailable')),
        ]);

        $aborted = null;
        try {
            $this->client($scriptedDeferredPlatform)->complete('sys', 'user');
        } catch (TransientLLMFailureException $transientllmFailureException) {
            $aborted = $transientllmFailureException->getMessage();
        }

        self::assertSame('LLM call failed after 3 attempts: Server error (HTTP 503). Service Unavailable', $aborted);
        self::assertSame(3, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_with_tools_reads_a_status_still_failing_once_the_retries_are_spent_as_the_bridge_reads_it(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform($this->alwaysFailingWithStatus(503, self::OLLAMA_EMPTY_ANSWER));

        $llmResponse = $this->client($scriptedDeferredPlatform)->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('empty_content', $llmResponse->stopReason());
        self::assertSame(3, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_reads_a_status_still_failing_once_the_retries_are_spent_as_the_bridge_reads_it(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform($this->alwaysFailingWithStatus(503, self::OLLAMA_EMPTY_ANSWER));

        $llmResponses = $this->client($scriptedDeferredPlatform)->completeBatch([['system' => 'sys', 'user' => 'user']], 2);

        self::assertSame('empty_content', $llmResponses[0]->stopReason());
        self::assertSame(4, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_reads_a_status_still_failing_once_the_retries_are_spent_as_the_bridge_reads_it(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform($this->alwaysFailingWithStatus(503, self::OLLAMA_EMPTY_ANSWER));

        $llmResponses = $this->client($scriptedDeferredPlatform)->completeBatchWithTools([['system' => 'sys', 'user' => 'user', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('empty_content', $llmResponses[0]->stopReason());
        self::assertSame(4, $scriptedDeferredPlatform->invocations);
    }

    private function failedWithStatus(int $status, string $bridgeMessage): DeferredResult
    {
        return $this->failedWithStatusAs($status, new PlatformRuntimeException($bridgeMessage));
    }

    private function failedWithStatusAs(int $status, RuntimeException $runtimeException): DeferredResult
    {
        $response = self::createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($status);
        $response->method('toArray')->willReturn(['error' => 'server busy, please try again.']);

        return new DeferredResult(new ThrowingConverter($runtimeException), new RawHttpResult($response), []);
    }

    /**
     * @return list<DeferredResult>
     */
    private function alwaysFailingWithStatus(int $status, string $bridgeMessage): array
    {
        return [$this->failedWithStatus($status, $bridgeMessage), $this->failedWithStatus($status, $bridgeMessage), $this->failedWithStatus($status, $bridgeMessage), $this->failedWithStatus($status, $bridgeMessage)];
    }

    private function answer(): DeferredResult
    {
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('[]')), new InMemoryRawResult(), []);
        $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: 20, completionTokens: 5));

        return $deferredResult;
    }

    private function client(PlatformInterface $platform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(
                new RetryPolicy(jitterSource: static fn (): float => 0.5),
                sleeper: $this->fakeSleeper,
                rateLimiter: $this->fakeRateLimiter,
            ),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $this->budgetTracker),
        );
    }

    private function freePricing(): PricingProviderInterface
    {
        return new class implements PricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }
}
