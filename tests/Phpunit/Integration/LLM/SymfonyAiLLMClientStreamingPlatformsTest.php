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
use Symfony\Component\HttpClient\Response\MockResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CallbackTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream\GeminiStreamedProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream\OpenAiStreamedProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream\ServerSentEvents;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream\StreamedProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\OneModelPricingProvider;

final class SymfonyAiLLMClientStreamingPlatformsTest extends TestCase
{
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
    #[DataProvider('streamedProviders')]
    public function test_a_streamed_answer_comes_back_whole_and_is_booked_at_the_usage_the_provider_reported(StreamedProviderInterface $streamedProvider): void
    {
        $response = $streamedProvider->textAnswer('Hello', 120, 7);
        $tokenUsageRecorder = new TokenUsageRecorder();

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($streamedProvider->platform($response), $streamedProvider->model(), new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $streamedProvider->servingPlatform(), streaming: true),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        ))->complete('system', 'user');

        self::assertSame(
            ['Hello', 120, 7, true],
            [$llmResponse->content(), $tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens(), $streamedProvider->askedForAStream($response)],
        );
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
    public function test_a_streamed_openai_answer_books_its_cache_reads_and_writes_apart_from_the_uncached_input(): void
    {
        $openAiStreamedProvider = new OpenAiStreamedProvider();
        $tokenUsageRecorder = new TokenUsageRecorder();

        (new SymfonyAiLLMClient(
            new PlatformBinding($openAiStreamedProvider->platform($openAiStreamedProvider->textAnswer('Hello', 15000, 300, ['cached_tokens' => 9000, 'cache_write_tokens' => 3000])), $openAiStreamedProvider->model(), new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $openAiStreamedProvider->servingPlatform(), streaming: true),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        ))->complete('system', 'user');

        self::assertSame(
            [3000, 9000, 3000],
            [$tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->cacheReadTokens(), $tokenUsageRecorder->snapshot()->cacheCreationTokens()],
        );
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
    public function test_a_streamed_openai_answer_the_output_limit_cut_off_makes_the_booked_cost_a_minimum(): void
    {
        $openAiStreamedProvider = new OpenAiStreamedProvider();
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator(new OneModelPricingProvider()));
        $incompleteResponse = ['id' => 'resp_1', 'status' => 'incomplete', 'model' => $openAiStreamedProvider->model(), 'incomplete_details' => ['reason' => 'max_output_tokens'], 'output' => [['type' => 'message', 'id' => 'msg_1', 'role' => 'assistant', 'content' => [['type' => 'output_text', 'text' => '[{"type": "sq']]]], 'usage' => ['input_tokens' => 50000, 'output_tokens' => 100000, 'total_tokens' => 150000]];
        $answer = ServerSentEvents::of(
            ['type' => 'response.created', 'response' => ['id' => 'resp_1', 'status' => 'in_progress', 'output' => [], 'usage' => null]],
            ['type' => 'response.output_text.delta', 'delta' => '[{"type": "sq'],
            ['type' => 'response.incomplete', 'response' => $incompleteResponse],
        );

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($openAiStreamedProvider->platform($answer), $openAiStreamedProvider->model(), new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $openAiStreamedProvider->servingPlatform(), streaming: true),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        ))->complete('system', 'user');

        self::assertSame(['length', 1], [$llmResponse->stopReason(), $budgetTracker->interruptedCalls()]);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    #[DataProvider('streamedProviders')]
    public function test_a_tool_call_the_model_streams_runs_and_the_conversation_goes_on(StreamedProviderInterface $streamedProvider): void
    {
        $lookedUp = [];
        $toolRegistry = new ToolRegistry([new CallbackTool('lookup', 'lookup', static function (array $arguments) use (&$lookedUp): string {
            $lookedUp[] = $arguments;

            return 'contents';
        }, ['type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path']])], new NullLogger());

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($streamedProvider->platform($streamedProvider->toolCallAnswer('lookup', ['path' => 'src/A.php']), $streamedProvider->textAnswer('done', 150, 2)), $streamedProvider->model(), new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $streamedProvider->servingPlatform(), streaming: true),
        ))->completeWithTools('system', 'user', $toolRegistry, 3);

        self::assertSame([[['path' => 'src/A.php']], 'done'], [$lookedUp, $llmResponse->content()]);
    }

    /**
     * @param array<string, mixed>       $reasoning
     * @param list<array<string, mixed>> $summaryEvents
     * @param list<string|null>          $expectedItemTypes
     *
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    #[DataProvider('reasoningItems')]
    public function test_a_streamed_openai_reasoning_item_is_sent_back_only_when_a_buffered_answer_keeps_it(array $reasoning, array $summaryEvents, array $expectedItemTypes): void
    {
        $openAiStreamedProvider = new OpenAiStreamedProvider();
        $functionCall = ['type' => 'function_call', 'id' => 'fc_1', 'call_id' => 'call_1', 'name' => 'lookup', 'arguments' => '{"path":"a.php"}', 'status' => 'completed'];
        $secondAnswer = $openAiStreamedProvider->textAnswer('done', 150, 2);
        $firstAnswer = ServerSentEvents::of(...[
            ['type' => 'response.created', 'response' => ['id' => 'resp_1', 'status' => 'in_progress', 'output' => [], 'usage' => null]],
            ['type' => 'response.output_item.added', 'output_index' => 0, 'item' => $reasoning],
            ...$summaryEvents,
            ['type' => 'response.output_item.done', 'output_index' => 0, 'item' => $reasoning],
            ['type' => 'response.output_item.added', 'output_index' => 1, 'item' => [...$functionCall, 'arguments' => '']],
            ['type' => 'response.function_call_arguments.delta', 'output_index' => 1, 'item_id' => 'fc_1', 'delta' => $functionCall['arguments']],
            ['type' => 'response.output_item.done', 'output_index' => 1, 'item' => $functionCall],
            ['type' => 'response.completed', 'response' => ['id' => 'resp_1', 'status' => 'completed', 'model' => $openAiStreamedProvider->model(), 'output' => [$reasoning, $functionCall], 'usage' => ['input_tokens' => 100, 'output_tokens' => 5, 'total_tokens' => 105]]],
        ]);

        (new SymfonyAiLLMClient(
            new PlatformBinding($openAiStreamedProvider->platform($firstAnswer, $secondAnswer), $openAiStreamedProvider->model(), new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $openAiStreamedProvider->servingPlatform(), streaming: true),
        ))->completeWithTools('system', 'user', new ToolRegistry([new CallbackTool('lookup', 'lookup')], new NullLogger()), 3);

        self::assertSame($expectedItemTypes, $this->sentItemTypes($secondAnswer));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, list<array<string, mixed>>, list<string|null>}>
     */
    public static function reasoningItems(): iterable
    {
        yield 'no summary and no encrypted content' => [['type' => 'reasoning', 'id' => 'rs_1', 'summary' => []], [], [null, 'function_call', 'function_call_output']];
        yield 'encrypted content' => [['type' => 'reasoning', 'id' => 'rs_1', 'summary' => [], 'encrypted_content' => 'gAAA'], [], [null, 'reasoning', 'function_call', 'function_call_output']];
        yield 'a summary' => [
            ['type' => 'reasoning', 'id' => 'rs_1', 'summary' => [['type' => 'summary_text', 'text' => 'Checking a.php']]],
            [['type' => 'response.reasoning_summary_text.delta', 'output_index' => 0, 'item_id' => 'rs_1', 'delta' => 'Checking a.php'], ['type' => 'response.reasoning_summary_text.done', 'output_index' => 0, 'item_id' => 'rs_1', 'text' => 'Checking a.php']],
            [null, 'reasoning', 'function_call', 'function_call_output'],
        ];
    }

    /**
     * @return list<mixed>
     */
    private function sentItemTypes(MockResponse $answer): array
    {
        $body = $answer->getRequestOptions()['body'] ?? '';
        self::assertIsString($body);
        $request = json_decode($body, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($request);
        self::assertIsArray($request['input']);

        return array_values(array_map(static fn (mixed $item): mixed => \is_array($item) ? $item['type'] ?? null : null, $request['input']));
    }

    /**
     * @return iterable<string, array{StreamedProviderInterface}>
     */
    public static function streamedProviders(): iterable
    {
        yield 'OpenAI (Responses API)' => [new OpenAiStreamedProvider()];
        yield 'Gemini' => [new GeminiStreamedProvider()];
    }
}
