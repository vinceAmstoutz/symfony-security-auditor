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
use Symfony\AI\Platform\Exception\RuntimeException as PlatformRuntimeException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\AnthropicUsageExtractor;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedCachePricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedResultTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\RawUsageExtractor;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * The rate-limit window is reconciled with the input a provider counts
 * against its input-tokens-per-minute limit, whatever share of it the cost
 * books at the cache rate: OpenAI-style providers count the cached tokens
 * inside the prompt, Anthropic counts its input and its cache writes, not
 * its cache reads.
 */
final class SymfonyAiLLMClientRateLimitedInputTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('usageConventions')]
    public function test_complete_reconciles_the_window_with_the_input_the_provider_meters(TokenUsage $tokenUsage, int $meteredInputTokens): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->client(ScriptedTokenUsagePlatform::scripted(new TextResult('[]'), $tokenUsage), $fakeRateLimiter)->complete('sys', 'usr');

        self::assertSame([[$meteredInputTokens, 50]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('usageConventions')]
    public function test_complete_batch_reconciles_the_window_with_the_input_the_provider_meters(TokenUsage $tokenUsage, int $meteredInputTokens): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->client(ScriptedTokenUsagePlatform::scripted(new TextResult('[]'), $tokenUsage), $fakeRateLimiter)->completeBatch([['system' => 'sys', 'user' => 'usr']], 2);

        self::assertSame([[$meteredInputTokens, 50]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('usageConventions')]
    public function test_complete_with_tools_reconciles_the_window_with_the_input_the_provider_meters(TokenUsage $tokenUsage, int $meteredInputTokens): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->client(ScriptedTokenUsagePlatform::scripted(new TextResult('[]'), $tokenUsage), $fakeRateLimiter)->completeWithTools('sys', 'usr', $this->toolRegistry(), 3);

        self::assertSame([[$meteredInputTokens, 50]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('usageConventions')]
    public function test_complete_batch_with_tools_reconciles_the_window_with_the_input_the_provider_meters(TokenUsage $tokenUsage, int $meteredInputTokens): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->client(ScriptedTokenUsagePlatform::scripted(new TextResult('[]'), $tokenUsage), $fakeRateLimiter)->completeBatchWithTools([['system' => 'sys', 'user' => 'usr', 'tools' => $this->toolRegistry()]], 2, 3);

        self::assertSame([[$meteredInputTokens, 50]], $fakeRateLimiter->recorded);
    }

    /**
     * @return iterable<string, array{TokenUsage, int}>
     */
    public static function usageConventions(): iterable
    {
        yield 'OpenAI-style usage, the cached tokens counted inside the prompt' => [new TokenUsage(promptTokens: 15000, completionTokens: 50, cachedTokens: 12000, totalTokens: 15050), 15000];
        yield 'Anthropic usage, the cache reads and writes reported apart' => [new TokenUsage(promptTokens: 20, completionTokens: 50, cacheCreationTokens: 2980, cacheReadTokens: 12000), 3000];
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_an_answer_the_bridge_reports_as_an_error_reconciles_the_window_with_the_input_the_provider_meters(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $deferredResult = new DeferredResult(
            new ThrowingConverter(new PlatformRuntimeException('Unsupported finish reason "content_filter".'), new RawUsageExtractor()),
            new InMemoryRawResult(['usage' => ['prompt_tokens' => 15000, 'completion_tokens' => 50, 'total_tokens' => 15050, 'prompt_tokens_details' => ['cached_tokens' => 12000]]]),
            [],
        );

        $this->client(new ScriptedDeferredPlatform([$deferredResult]), $fakeRateLimiter)->complete('sys', 'usr');

        self::assertSame([[15000, 50]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_the_response_still_books_the_cached_share_of_an_openai_style_prompt_apart_from_its_input(): void
    {
        $llmResponse = $this->client(
            ScriptedTokenUsagePlatform::scripted(new TextResult('[]'), new TokenUsage(promptTokens: 15000, completionTokens: 50, cachedTokens: 12000, totalTokens: 15050)),
            new FakeRateLimiter(),
        )->complete('sys', 'usr');

        self::assertSame([3000, 12000], [$llmResponse->inputTokens(), $llmResponse->cacheReadTokens()]);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_a_usage_that_reports_no_prompt_reconciles_the_window_with_the_estimate_its_cache_reads_are_part_of(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->client(
            ScriptedTokenUsagePlatform::scripted(new TextResult('[]'), new TokenUsage(completionTokens: 50, cacheReadTokens: 12000, totalTokens: 12050)),
            $fakeRateLimiter,
        )->complete('sys', 'usr');

        self::assertSame([[$fakeRateLimiter->acquired[0], 50]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_counts_the_cache_writes_kept_for_an_hour_in_the_window_and_prices_them_at_their_own_rate(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $budgetTracker = $this->budgetTracker();

        $this->budgetedClient(new ScriptedDeferredPlatform([$this->anthropicAnswer(new TextResult('[]'), 10000, 30000)]), $fakeRateLimiter, $budgetTracker)->complete('sys', 'usr');

        self::assertSame([[[40012, 200]], 0.220536], [$fakeRateLimiter->recorded, $budgetTracker->costUsdUsed()]);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_counts_the_cache_writes_kept_for_an_hour_in_the_window_and_prices_them_at_their_own_rate(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $budgetTracker = $this->budgetTracker();

        $this->budgetedClient(new ScriptedDeferredPlatform([$this->anthropicAnswer(new TextResult('[]'), 10000, 30000)]), $fakeRateLimiter, $budgetTracker)->completeBatch([['system' => 'sys', 'user' => 'usr']], 2);

        self::assertSame([[[40012, 200]], 0.220536], [$fakeRateLimiter->recorded, $budgetTracker->costUsdUsed()]);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_with_tools_counts_the_cache_writes_kept_for_an_hour_in_the_window_of_every_round(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $budgetTracker = $this->budgetTracker();
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            $this->anthropicAnswer(new ToolCallResult([new ToolCall('call-1', 'read_file', [])]), 0, 40000),
            $this->anthropicAnswer(new TextResult('done'), 0, 1000),
        ]);

        $this->budgetedClient($scriptedDeferredPlatform, $fakeRateLimiter, $budgetTracker)->completeWithTools('sys', 'usr', $this->toolRegistry(), 3);

        self::assertSame([[[40012, 200], [1012, 200]], 0.252072], [$fakeRateLimiter->recorded, $budgetTracker->costUsdUsed()]);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_an_answer_the_bridge_reports_as_an_error_counts_its_cache_writes_kept_for_an_hour_in_the_window(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $budgetTracker = $this->budgetTracker();
        $deferredResult = new DeferredResult(
            new ThrowingConverter(new PlatformRuntimeException('Response does not contain any content.'), new AnthropicUsageExtractor()),
            new InMemoryRawResult($this->anthropicMessage(0, 40000)),
            [],
        );

        $this->budgetedClient(new ScriptedDeferredPlatform([$deferredResult]), $fakeRateLimiter, $budgetTracker)->complete('sys', 'usr');

        self::assertSame([[[40012, 200]], 0.243036], [$fakeRateLimiter->recorded, $budgetTracker->costUsdUsed()]);
    }

    /**
     * @throws InvalidToolRegistryException
     */
    private function toolRegistry(): ToolRegistry
    {
        return new ToolRegistry([new FixedResultTool('read_file', 'contents')], new NullLogger());
    }

    private function budgetTracker(): BudgetTracker
    {
        return new BudgetTracker(AuditBudget::unlimited(), new CostCalculator(new FixedCachePricingProvider(3.0, 15.0, 0.3, 3.75)));
    }

    private function anthropicAnswer(ResultInterface $result, int $fiveMinuteWrites, int $oneHourWrites): DeferredResult
    {
        $inMemoryRawResult = new InMemoryRawResult($this->anthropicMessage($fiveMinuteWrites, $oneHourWrites));
        $deferredResult = new DeferredResult(new PlainConverter($result), $inMemoryRawResult, []);
        $deferredResult->getMetadata()->add('token_usage', (new AnthropicUsageExtractor())->extract($inMemoryRawResult));

        return $deferredResult;
    }

    /**
     * @return array<string, mixed>
     */
    private function anthropicMessage(int $fiveMinuteWrites, int $oneHourWrites): array
    {
        return [
            'id' => 'msg_1',
            'type' => 'message',
            'role' => 'assistant',
            'model' => 'claude-sonnet-4-5-20250929',
            'content' => [['type' => 'text', 'text' => '[]']],
            'stop_reason' => 'end_turn',
            'usage' => [
                'input_tokens' => 12,
                'cache_creation_input_tokens' => $fiveMinuteWrites + $oneHourWrites,
                'cache_read_input_tokens' => 0,
                'output_tokens' => 200,
                'cache_creation' => ['ephemeral_5m_input_tokens' => $fiveMinuteWrites, 'ephemeral_1h_input_tokens' => $oneHourWrites],
            ],
        ];
    }

    private function budgetedClient(PlatformInterface $platform, FakeRateLimiter $fakeRateLimiter, BudgetTracker $budgetTracker): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'claude-sonnet-4-5', new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(1000)),
            new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
            new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        );
    }

    private function client(PlatformInterface $platform, FakeRateLimiter $fakeRateLimiter): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
        );
    }
}
