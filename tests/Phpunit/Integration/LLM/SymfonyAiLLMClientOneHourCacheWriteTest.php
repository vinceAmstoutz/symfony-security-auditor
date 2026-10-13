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
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Exception\RuntimeException as PlatformRuntimeException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedCachePricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedResultTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * Anthropic keeps a prompt-cache write for five minutes or, with
 * `cache_retention: long`, for an hour, and bills an hour-long write at twice
 * the base input rate where a five-minute one costs 1.25 times it. The
 * bridge's usage counts every write alike; only the raw answer tells them
 * apart, so each share is priced at its own rate.
 */
final class SymfonyAiLLMClientOneHourCacheWriteTest extends TestCase
{
    private BudgetTracker $budgetTracker;

    #[Override]
    protected function setUp(): void
    {
        $this->budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator(new FixedCachePricingProvider(3.0, 15.0, 0.3, 3.75)));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    #[DataProvider('oneHourCacheWriteCases')]
    public function test_complete_prices_the_one_hour_cache_writes_an_anthropic_answer_reports_at_twice_the_input_rate(int $fiveMinuteWrites, int $oneHourWrites, float $expectedCostUsd): void
    {
        $this->client(new ScriptedDeferredPlatform([$this->anthropicAnswer(new TextResult('[]'), $fiveMinuteWrites, $oneHourWrites)]))->complete('sys', 'user');

        self::assertSame($expectedCostUsd, $this->budgetTracker->costUsdUsed());
    }

    /** @return iterable<string, array{int, int, float}> */
    public static function oneHourCacheWriteCases(): iterable
    {
        yield 'every write kept for an hour' => [0, 40000, 0.243036];
        yield 'writes kept for five minutes and for an hour' => [10000, 30000, 0.220536];
    }

    /**
     * @param array<string, mixed> $usage
     *
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    #[DataProvider('answersWithNoOneHourCacheWriteCases')]
    public function test_complete_keeps_pricing_cache_writes_no_answer_reports_as_kept_for_an_hour_at_the_cache_write_rate(array $usage): void
    {
        $this->client(new ScriptedDeferredPlatform([$this->convertedAnthropicAnswer(new TextResult('[]'), $this->anthropicMessage(40000, $usage))]))->complete('sys', 'user');

        self::assertSame(0.153036, $this->budgetTracker->costUsdUsed());
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function answersWithNoOneHourCacheWriteCases(): iterable
    {
        yield 'writes kept for five minutes' => [['cache_creation' => ['ephemeral_5m_input_tokens' => 40000, 'ephemeral_1h_input_tokens' => 0]]];
        yield 'an answer that does not split its writes' => [[]];
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolDefinitionException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     */
    public function test_complete_with_tools_prices_the_one_hour_cache_writes_of_every_round_at_twice_the_input_rate(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            $this->anthropicAnswer(new ToolCallResult([new ToolCall('call-1', 'lookup', [])]), fiveMinuteWrites: 0, oneHourWrites: 40000),
            $this->anthropicAnswer(new TextResult('done'), fiveMinuteWrites: 0, oneHourWrites: 1000),
        ]);

        $this->client($scriptedDeferredPlatform)->completeWithTools('sys', 'user', new ToolRegistry([new FixedResultTool('lookup', 'found')], new NullLogger()), 3);

        self::assertSame(0.252072, $this->budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_complete_batch_prices_the_one_hour_cache_writes_of_every_answer_at_twice_the_input_rate(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            $this->anthropicAnswer(new TextResult('[]'), fiveMinuteWrites: 0, oneHourWrites: 40000),
            $this->anthropicAnswer(new TextResult('[]'), fiveMinuteWrites: 0, oneHourWrites: 1000),
        ]);

        $this->client($scriptedDeferredPlatform)->completeBatch([['system' => 'sys', 'user' => 'first'], ['system' => 'sys', 'user' => 'second']], 2);

        self::assertSame(0.252072, $this->budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_complete_prices_the_one_hour_cache_writes_of_an_answer_the_bridge_reports_as_an_error_at_twice_the_input_rate(): void
    {
        $deferredResult = new DeferredResult(
            new ThrowingConverter(new PlatformRuntimeException('Response does not contain any content.'), new AnthropicUsageExtractor()),
            new InMemoryRawResult($this->anthropicMessage(40000, ['cache_creation' => ['ephemeral_5m_input_tokens' => 0, 'ephemeral_1h_input_tokens' => 40000]])),
            [],
        );

        $this->client(new ScriptedDeferredPlatform([$deferredResult]))->complete('sys', 'user');

        self::assertSame(0.243036, $this->budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_complete_books_an_answer_cut_off_before_it_came_back_at_its_estimated_input_alone(): void
    {
        $this->client(new ScriptedDeferredPlatform([new MaxOutputTokensException('cut off')]))->complete('sys', 'user');

        self::assertSame(0.006, $this->budgetTracker->costUsdUsed());
    }

    private function anthropicAnswer(ResultInterface $result, int $fiveMinuteWrites, int $oneHourWrites): DeferredResult
    {
        return $this->convertedAnthropicAnswer($result, $this->anthropicMessage($fiveMinuteWrites + $oneHourWrites, ['cache_creation' => ['ephemeral_5m_input_tokens' => $fiveMinuteWrites, 'ephemeral_1h_input_tokens' => $oneHourWrites]]));
    }

    /**
     * An answer the Anthropic bridge converted, carrying the usage its
     * extractor read from the raw answer.
     *
     * @param array<string, mixed> $anthropicMessage
     */
    private function convertedAnthropicAnswer(ResultInterface $result, array $anthropicMessage): DeferredResult
    {
        $inMemoryRawResult = new InMemoryRawResult($anthropicMessage);
        $deferredResult = new DeferredResult(new PlainConverter($result), $inMemoryRawResult, []);
        $deferredResult->getMetadata()->add('token_usage', (new AnthropicUsageExtractor())->extract($inMemoryRawResult));

        return $deferredResult;
    }

    /**
     * @param array<string, mixed> $usage what the answer's usage reports beside its token counts
     *
     * @return array<string, mixed>
     */
    private function anthropicMessage(int $cacheWrites, array $usage): array
    {
        return [
            'id' => 'msg_1',
            'type' => 'message',
            'role' => 'assistant',
            'model' => 'claude-sonnet-4-5-20250929',
            'content' => [['type' => 'text', 'text' => '[]']],
            'stop_reason' => 'end_turn',
            'usage' => ['input_tokens' => 12, 'cache_creation_input_tokens' => $cacheWrites, 'cache_read_input_tokens' => 0, 'output_tokens' => 200] + $usage,
        ];
    }

    private function client(PlatformInterface $platform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'claude-sonnet-4-5', new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(1000)),
            new PlatformResilienceConfig(sleeper: new FakeSleeper()),
            new PlatformAccountingConfig(budgetTracker: $this->budgetTracker),
        );
    }
}
