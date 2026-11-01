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
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
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
    public function test_provider_streaming_streams_the_calls_of_a_platform_that_reports_usage_in_its_stream(): void
    {
        $response = self::sse(self::messageStart(120), ...self::textBlock(0, 'Hello'), ...self::messageEnd('end_turn', 2));
        $platform = $this->platform($response);

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($platform, self::MODEL, new NullLogger()),
            new PlatformRequestConfig(servingPlatform: 'anthropic', providerStreaming: true),
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
    public function test_a_call_stays_buffered_unless_streaming_is_on_for_a_platform_that_reports_usage_in_its_stream(?string $servingPlatform, bool $providerStreaming): void
    {
        $response = new MockResponse(self::json(['id' => 'msg_1', 'type' => 'message', 'role' => 'assistant', 'model' => self::MODEL, 'content' => [['type' => 'text', 'text' => 'Hello']], 'stop_reason' => 'end_turn', 'usage' => ['input_tokens' => 120, 'output_tokens' => 2]]));
        $platform = $this->platform($response);

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($platform, self::MODEL, new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $servingPlatform, providerStreaming: $providerStreaming),
        ))->complete('system', 'user');

        self::assertSame(['Hello', false], [$llmResponse->content(), $this->request($response)['stream'] ?? false]);
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function bufferedCallCases(): iterable
    {
        yield 'streaming off' => ['anthropic', false];
        yield 'a platform whose stream usage is not verified' => ['mistral', true];
        yield 'no known platform' => [null, true];
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
            new PlatformRequestConfig(servingPlatform: 'anthropic', providerStreaming: true),
        );

        $this->expectException(MissingAiPlatformException::class);

        $symfonyAiLLMClient->complete('system', 'user');
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
