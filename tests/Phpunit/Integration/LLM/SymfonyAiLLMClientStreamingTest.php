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

use Generator;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Bridge\Anthropic\Factory;
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\FinishReason\FinishReasonCase;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\Stream\Delta\DeltaInterface;
use Symfony\AI\Platform\Result\Stream\Delta\MetadataDelta;
use Symfony\AI\Platform\Result\Stream\Delta\TextDelta;
use Symfony\AI\Platform\Result\StreamResult;
use Symfony\AI\Platform\Test\MockPlatformFactory;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\AI\Platform\TraceablePlatform;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\StreamingPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CallbackTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\MetadataUsagePlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\OneModelPricingProvider;

final class SymfonyAiLLMClientStreamingTest extends TestCase
{
    private const string MODEL = 'claude-opus-5-5';

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
    public function test_a_streamed_answer_comes_back_whole_with_the_usage_the_stream_reported(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello', ' world'), ...self::messageEnd('end_turn', 7)));

        $llmResponse = $this->streamingClient($platform)->complete('system', 'user');

        self::assertSame(['Hello world', 120, 7, 'end_turn'], [$llmResponse->content(), $llmResponse->inputTokens(), $llmResponse->outputTokens(), $llmResponse->stopReason()]);
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
    public function test_a_stream_the_model_refused_is_the_content_filter_answer_a_buffered_refusal_gives(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(120), ...self::textBlock(0, 'I cannot help with that.'), ...self::messageEnd('refusal', 6)));

        $llmResponse = $this->streamingClient($platform)->complete('system', 'user');

        self::assertSame(['content-filter', true], [$llmResponse->stopReason(), $llmResponse->isDegraded()]);
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
    public function test_a_stream_the_output_limit_cut_off_is_the_degraded_answer_a_buffered_call_cut_off_gives(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(120), ...self::textBlock(0, '[{"type": "sq'), ...self::messageEnd('max_tokens', 4096)));

        $llmResponse = $this->streamingClient($platform)->complete('system', 'user');

        self::assertSame(['length', true], [$llmResponse->stopReason(), $llmResponse->isDegraded()]);
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
    public function test_a_stream_that_ends_without_a_finish_reason_was_cut_and_is_sent_again(): void
    {
        $answers = [
            self::streamedAnswer(new TextDelta('Hel'), new TokenUsage(promptTokens: 120, completionTokens: 1)),
            self::streamedAnswer(new TextDelta('Hello'), new TokenUsage(promptTokens: 120, completionTokens: 2), new MetadataDelta('finish_reason', new FinishReason(FinishReasonCase::STOP, 'STOP'))),
        ];
        $platform = MockPlatformFactory::createPlatform(static function () use (&$answers): StreamResult {
            return array_shift($answers) ?? throw new LogicException('No answer left');
        });

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        ))->complete('system', 'user');

        self::assertSame('Hello', $llmResponse->content());
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
    public function test_a_platform_whose_stream_reports_no_usage_is_called_without_streaming_from_then_on(): void
    {
        $streamed = [];
        $platform = MockPlatformFactory::createPlatform(static function (Model $model, array|string|object $input, array $options) use (&$streamed): StreamResult|string {
            $streamed[] = true === ($options['stream'] ?? false);

            return true === ($options['stream'] ?? false)
                ? self::streamedAnswer(new TextDelta('Hello'), new MetadataDelta('finish_reason', new FinishReason(FinishReasonCase::STOP, 'stop')))
                : 'Hello';
        });
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );

        $answers = [$symfonyAiLLMClient->complete('system', 'user')->content(), $symfonyAiLLMClient->complete('system', 'user')->content()];

        self::assertSame([['Hello', 'Hello'], [true, false, false]], [$answers, $streamed]);
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
    public function test_a_gateway_that_answers_a_streamed_request_in_one_piece_is_read_and_billed_as_it_answered_and_no_longer_streamed(): void
    {
        $answer = static fn (): MockResponse => new MockResponse(self::json(['id' => 'msg_1', 'type' => 'message', 'role' => 'assistant', 'model' => self::MODEL, 'content' => [['type' => 'text', 'text' => 'Hello']], 'stop_reason' => 'end_turn', 'usage' => ['input_tokens' => 120, 'output_tokens' => 7]]), ['response_headers' => ['content-type' => 'application/json']]);
        $responses = [$answer(), $answer()];
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator(new OneModelPricingProvider()));
        $tokenUsageRecorder = new TokenUsageRecorder();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($this->platform(...$responses)), self::MODEL, new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder, budgetTracker: $budgetTracker),
        );

        $contents = [$symfonyAiLLMClient->complete('system', 'user')->content(), $symfonyAiLLMClient->complete('system', 'user')->content()];

        self::assertSame(
            [['Hello', 'Hello'], 240, 14, 0, false],
            [$contents, $tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens(), $budgetTracker->interruptedCalls(), $this->request($responses[1])['stream'] ?? false],
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
    public function test_a_provider_that_refuses_a_streamed_request_is_reported_in_its_own_words(): void
    {
        $platform = $this->platform(new MockResponse(self::json(['type' => 'error', 'error' => ['type' => 'authentication_error', 'message' => 'invalid x-api-key']]), ['http_code' => 401, 'response_headers' => ['content-type' => 'application/json']]));

        $this->expectException(NonTransientLLMFailureException::class);
        $this->expectExceptionMessage('invalid x-api-key');

        $this->streamingClient($platform)->complete('system', 'user');
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
    public function test_a_stream_a_debug_kernel_traces_is_booked_once_at_the_usage_it_reported(): void
    {
        $platform = new TraceablePlatform($this->platform(self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello'), ...self::messageEnd('end_turn', 7))));
        $tokenUsageRecorder = new TokenUsageRecorder();

        (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        ))->complete('system', 'user');

        self::assertSame([120, 7], [$tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens()]);
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
    public function test_a_stream_that_carries_no_content_is_the_degraded_answer_a_buffered_call_without_content_gives(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(120), ...self::messageEnd('end_turn', 1)));

        $llmResponse = $this->streamingClient($platform)->complete('system', 'user');

        self::assertSame(['empty_content', true], [$llmResponse->stopReason(), $llmResponse->isDegraded()]);
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
    public function test_a_stream_that_carries_no_content_is_booked_at_the_usage_it_reported(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(120), ...self::messageEnd('end_turn', 3)));
        $tokenUsageRecorder = new TokenUsageRecorder();

        (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        ))->complete('system', 'user');

        self::assertSame([120, 3], [$tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens()]);
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
    public function test_a_stream_cut_before_its_end_is_sent_again_as_a_whole_call(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(120), ...\array_slice(self::textBlock(0, 'Hel'), 0, 2)), self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello'), ...self::messageEnd('end_turn', 2)));

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        ))->complete('system', 'user');

        self::assertSame('Hello', $llmResponse->content());
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
    public function test_a_stream_cut_before_its_end_is_booked_at_the_usage_it_reported_before_the_cut(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(120), ...\array_slice(self::textBlock(0, 'Hel'), 0, 1)), self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello'), ...self::messageEnd('end_turn', 2)));
        $tokenUsageRecorder = new TokenUsageRecorder();

        (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        ))->complete('system', 'user');

        self::assertSame([240, 2], [$tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens()]);
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
    public function test_a_stream_cut_before_its_end_makes_the_booked_cost_a_minimum(): void
    {
        $platform = $this->platform(
            self::sse(self::messageStart(120), ...\array_slice(self::textBlock(0, 'Hel'), 0, 1)),
            self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello'), ...self::messageEnd('end_turn', 2)),
        );
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator(new OneModelPricingProvider()));

        (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        ))->complete('system', 'user');

        self::assertSame(1, $budgetTracker->interruptedCalls());
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
    public function test_a_buffered_call_the_connection_cut_makes_the_booked_cost_a_minimum(): void
    {
        $attempts = 0;
        $platform = MockPlatformFactory::createPlatform(static function () use (&$attempts): string {
            return 1 === ++$attempts ? throw new TransportException('Transfer closed with 512 bytes remaining to read') : 'Hello';
        });
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator(new OneModelPricingProvider()));

        (new SymfonyAiLLMClient(
            new PlatformBinding($platform, self::MODEL, new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        ))->complete('system', 'user');

        self::assertSame(1, $budgetTracker->interruptedCalls());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws InvalidToolRegistryException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    public function test_a_stream_cut_in_a_concurrent_conversation_makes_the_booked_cost_a_minimum(): void
    {
        $platform = $this->platform(
            self::sse(self::messageStart(120), ...\array_slice(self::textBlock(0, 'Hel'), 0, 1)),
            self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello'), ...self::messageEnd('end_turn', 2)),
        );
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator(new OneModelPricingProvider()));

        (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        ))->completeBatchWithTools([['system' => 'system', 'user' => 'user', 'tools' => new ToolRegistry([new CallbackTool('lookup', 'lookup')], new NullLogger())]], 2, 3);

        self::assertSame(1, $budgetTracker->interruptedCalls());
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
    public function test_a_tool_call_streamed_by_the_model_runs_and_the_conversation_goes_on(): void
    {
        $platform = $this->platform(self::sse(self::messageStart(100), ...$this->toolUseBlock(0, 'toolu_1', '{"path": "src/A.php"}'), ...self::messageEnd('tool_use', 5)), self::sse(self::messageStart(150), ...self::textBlock(0, 'done'), ...self::messageEnd('end_turn', 2)));
        $lookedUp = [];
        $toolRegistry = new ToolRegistry([new CallbackTool('lookup', 'lookup', static function (array $arguments) use (&$lookedUp): string {
            $lookedUp[] = $arguments;

            return 'contents';
        })], new NullLogger());

        $llmResponse = $this->streamingClient($platform)->completeWithTools('system', 'user', $toolRegistry, 3);

        self::assertSame([[['path' => 'src/A.php']], 'done'], [$lookedUp, $llmResponse->content()]);
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
    public function test_a_streamed_request_carries_the_output_limit_and_the_tools_a_buffered_one_carries(): void
    {
        $response = self::sse(self::messageStart(100), ...self::textBlock(0, 'done'), ...self::messageEnd('end_turn', 1));
        $platform = $this->platform($response);

        (new SymfonyAiLLMClient(new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger(), maxOutputTokens: 8192)))
            ->completeWithTools('system', 'user', new ToolRegistry([new CallbackTool('lookup', 'lookup')], new NullLogger()), 3);

        $request = $this->request($response);
        self::assertIsArray($request['tools']);
        self::assertSame([8192, ['lookup']], [$request['max_tokens'] ?? null, array_column($request['tools'], 'name')]);
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
    public function test_the_streamed_turn_goes_back_with_the_tool_result_in_the_order_the_model_produced_it(): void
    {
        $responses = [
            self::sse(
                self::messageStart(100),
                ...$this->thinkingBlock(0, 'Check A first.', 'sig-1'),
                ...$this->toolUseBlock(1, 'toolu_1', '{}'),
                ...self::textBlock(2, 'Then B.'),
                ...$this->toolUseBlock(3, 'toolu_2', '{}'),
                ...self::messageEnd('tool_use', 9),
            ),
            self::sse(self::messageStart(150), ...self::textBlock(0, 'done'), ...self::messageEnd('end_turn', 1)),
        ];
        $platform = $this->platform(...$responses);

        $this->streamingClient($platform)->completeWithTools('system', 'user', new ToolRegistry([new CallbackTool('lookup', 'lookup')], new NullLogger()), 3);

        self::assertSame([
            ['type' => 'thinking', 'thinking' => 'Check A first.', 'signature' => 'sig-1'],
            ['type' => 'tool_use', 'id' => 'toolu_1'],
            ['type' => 'text', 'text' => 'Then B.'],
            ['type' => 'tool_use', 'id' => 'toolu_2'],
        ], $this->replayedAssistantTurn($this->request($responses[1])));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    public function test_concurrent_conversations_each_get_their_own_streamed_answer(): void
    {
        $platform = Factory::createPlatform('sk-test', new MockHttpClient(static function (string $method, string $url, array $options): MockResponse {
            $answer = str_contains(self::requestBody($options), 'first') ? 'one' : 'two';

            return self::sse(self::messageStart(50), ...self::textBlock(0, $answer), ...self::messageEnd('end_turn', 1));
        }));
        $toolRegistry = new ToolRegistry([new CallbackTool('lookup', 'lookup')], new NullLogger());

        $llmResponses = $this->streamingClient($platform)->completeBatchWithTools([
            ['system' => 'system', 'user' => 'first', 'tools' => $toolRegistry],
            ['system' => 'system', 'user' => 'second', 'tools' => $toolRegistry],
        ], 2, 3);

        self::assertSame(['one', 'two'], array_map(static fn (LLMResponse $llmResponse): string => $llmResponse->content(), $llmResponses));
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
    public function test_a_client_set_to_stream_streams_the_calls_of_a_platform_that_reports_usage_in_its_stream(): void
    {
        $response = self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello'), ...self::messageEnd('end_turn', 2));
        $platform = $this->platform($response);

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($platform, self::MODEL, new NullLogger()),
            new PlatformRequestConfig(servingPlatform: 'anthropic', streaming: true),
        ))->complete('system', 'user');

        self::assertSame(['Hello', true], [$llmResponse->content(), $this->request($response)['stream'] ?? false]);
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
    #[DataProvider('bufferedCallCases')]
    public function test_a_call_stays_buffered_when_streaming_is_off_or_the_stream_of_its_platform_cannot_be_trusted(?string $servingPlatform, bool $streaming): void
    {
        $response = new MockResponse(self::json(['id' => 'msg_1', 'type' => 'message', 'role' => 'assistant', 'model' => self::MODEL, 'content' => [['type' => 'text', 'text' => 'Hello']], 'stop_reason' => 'end_turn', 'usage' => ['input_tokens' => 120, 'output_tokens' => 2]]));
        $platform = $this->platform($response);

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($platform, self::MODEL, new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $servingPlatform, streaming: $streaming),
        ))->complete('system', 'user');

        self::assertSame(['Hello', false], [$llmResponse->content(), $this->request($response)['stream'] ?? false]);
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
    public function test_a_platform_that_answers_a_streamed_request_in_one_piece_is_booked_at_the_usage_it_states(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        (new SymfonyAiLLMClient(
            new PlatformBinding(new StreamingPlatform(new MetadataUsagePlatform('answer', 120, 7)), self::MODEL, new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        ))->complete('system', 'user');

        self::assertSame([120, 7], [$tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens()]);
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
    public function test_a_platform_that_answers_a_streamed_request_in_one_piece_is_read_as_it_answered(): void
    {
        $llmResponse = $this->streamingClient(MockPlatformFactory::createPlatform('answer'))->complete('system', 'user');

        self::assertSame('answer', $llmResponse->content());
    }

    /**
     * @param array<string, mixed>|null $streamOptions
     *
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    #[DataProvider('streamOptionsCases')]
    public function test_a_streamed_call_asks_for_its_usage_where_the_bridge_does_not(string $servingPlatform, ?array $streamOptions): void
    {
        $sentOptions = [];
        $platform = MockPlatformFactory::createPlatform(static function (Model $model, array|string|object $input, array $options) use (&$sentOptions): StreamResult {
            $sentOptions = $options;

            return self::streamedAnswer(new TextDelta('Hello'), new TokenUsage(promptTokens: 1, completionTokens: 1), new MetadataDelta('finish_reason', new FinishReason(FinishReasonCase::STOP, 'stop')));
        });

        (new SymfonyAiLLMClient(
            new PlatformBinding($platform, self::MODEL, new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $servingPlatform, streaming: true),
        ))->complete('system', 'user');

        self::assertSame($streamOptions, $sentOptions['stream_options'] ?? null);
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>|null}>
     */
    public static function streamOptionsCases(): iterable
    {
        yield 'DeepSeek' => ['deepseek', ['include_usage' => true]];
        yield 'Mistral' => ['mistral', ['include_usage' => true]];
        yield 'Anthropic, whose stream always reports its usage' => ['anthropic', null];
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function bufferedCallCases(): iterable
    {
        yield 'streaming off' => ['anthropic', false];
        yield 'no known platform' => [null, true];
        yield 'Vertex AI, which adds up running usage totals' => ['vertexai', true];
        yield 'Venice, which adds up its usage chunks' => ['venice', true];
        yield 'Cohere, whose stream reports no usage' => ['cohere', true];
        yield 'MiniMax, whose stream reports no usage nor tool calls' => ['minimax', true];
        yield 'Bedrock, whose native routes do not stream' => ['bedrock', true];
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
    public function test_streaming_on_without_a_platform_still_names_the_missing_platform(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(null, self::MODEL, new NullLogger()),
            new PlatformRequestConfig(servingPlatform: 'anthropic', streaming: true),
        );

        $this->expectException(MissingAiPlatformException::class);

        $symfonyAiLLMClient->complete('system', 'user');
    }

    private static function streamedAnswer(DeltaInterface ...$deltas): StreamResult
    {
        return new StreamResult((static function () use ($deltas): Generator {
            yield from $deltas;
        })());
    }

    private function streamingClient(PlatformInterface $platform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(new PlatformBinding(new StreamingPlatform($platform), self::MODEL, new NullLogger()));
    }

    private function platform(MockResponse ...$responses): PlatformInterface
    {
        return Factory::createPlatform('sk-test', new MockHttpClient($responses));
    }

    /**
     * @return array<array-key, mixed>
     */
    private function request(MockResponse $mockResponse): array
    {
        $request = json_decode(self::requestBody($mockResponse->getRequestOptions()), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($request);

        return $request;
    }

    /**
     * @param array<array-key, mixed> $options
     */
    private static function requestBody(array $options): string
    {
        self::assertIsString($options['body']);

        return $options['body'];
    }

    /**
     * @param array<array-key, mixed> $request
     *
     * @return list<array<array-key, mixed>>
     */
    private function replayedAssistantTurn(array $request): array
    {
        self::assertIsArray($request['messages']);
        self::assertIsArray($request['messages'][1]);
        self::assertIsArray($request['messages'][1]['content']);

        $replayedTurn = [];
        foreach ($request['messages'][1]['content'] as $block) {
            self::assertIsArray($block);
            $replayedTurn[] = array_intersect_key($block, ['type' => true, 'thinking' => true, 'signature' => true, 'text' => true, 'id' => true]);
        }

        return $replayedTurn;
    }

    /**
     * @return array<string, mixed>
     */
    private static function messageStart(int $inputTokens): array
    {
        return ['type' => 'message_start', 'message' => ['id' => 'msg_1', 'type' => 'message', 'role' => 'assistant', 'model' => self::MODEL, 'content' => [], 'stop_reason' => null, 'usage' => ['input_tokens' => $inputTokens, 'output_tokens' => 1]]];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function textBlock(int $index, string ...$deltas): array
    {
        return [
            ['type' => 'content_block_start', 'index' => $index, 'content_block' => ['type' => 'text', 'text' => '']],
            ...array_map(static fn (string $delta): array => ['type' => 'content_block_delta', 'index' => $index, 'delta' => ['type' => 'text_delta', 'text' => $delta]], array_values($deltas)),
            ['type' => 'content_block_stop', 'index' => $index],
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function thinkingBlock(int $index, string $thinking, string $signature): array
    {
        return [
            ['type' => 'content_block_start', 'index' => $index, 'content_block' => ['type' => 'thinking', 'thinking' => '']],
            ['type' => 'content_block_delta', 'index' => $index, 'delta' => ['type' => 'thinking_delta', 'thinking' => $thinking]],
            ['type' => 'content_block_delta', 'index' => $index, 'delta' => ['type' => 'signature_delta', 'signature' => $signature]],
            ['type' => 'content_block_stop', 'index' => $index],
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function toolUseBlock(int $index, string $id, string $input): array
    {
        return [
            ['type' => 'content_block_start', 'index' => $index, 'content_block' => ['type' => 'tool_use', 'id' => $id, 'name' => 'lookup', 'input' => []]],
            ['type' => 'content_block_delta', 'index' => $index, 'delta' => ['type' => 'input_json_delta', 'partial_json' => $input]],
            ['type' => 'content_block_stop', 'index' => $index],
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function messageEnd(string $stopReason, int $outputTokens): array
    {
        return [
            ['type' => 'message_delta', 'delta' => ['stop_reason' => $stopReason, 'stop_sequence' => null], 'usage' => ['output_tokens' => $outputTokens]],
            ['type' => 'message_stop'],
        ];
    }

    /**
     * @param array<string, mixed> ...$events
     */
    private static function sse(array ...$events): MockResponse
    {
        $body = '';
        foreach ($events as $event) {
            self::assertIsString($event['type']);
            $body .= \sprintf("event: %s\ndata: %s\n\n", $event['type'], self::json($event));
        }

        return new MockResponse($body, ['response_headers' => ['content-type' => 'text/event-stream']]);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function json(array $payload): string
    {
        return json_encode($payload, \JSON_THROW_ON_ERROR);
    }
}
