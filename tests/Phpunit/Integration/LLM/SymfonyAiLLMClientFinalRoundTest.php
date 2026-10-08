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

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Message\MessageInterface;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\Message\UserMessage;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\FinalRound;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CountingRecordingTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedResultTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\RefusingRecordingTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedResultPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ToolCallCounter;

final class SymfonyAiLLMClientFinalRoundTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_last_round_that_records_its_findings_ends_the_conversation_as_answered(): void
    {
        $toolCallCounter = new ToolCallCounter();
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('record'),
        ]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry($toolCallCounter), 2);

        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertFalse($llmResponse->isDegraded());
        self::assertSame(1, $toolCallCounter->calls);
        self::assertCount(2, $scriptedResultPlatform->requests);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_last_round_that_reads_and_records_ends_the_conversation_as_answered(): void
    {
        $toolCallCounter = new ToolCallCounter();
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('lookup', 'record'),
        ]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry($toolCallCounter), 2);

        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertSame(1, $toolCallCounter->calls);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_round_that_records_before_the_last_one_does_not_end_the_conversation(): void
    {
        $toolCallCounter = new ToolCallCounter();
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('record'),
            new MultiPartResult([new TextResult('done')]),
        ]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry($toolCallCounter), 3);

        self::assertSame('done', $llmResponse->content());
        self::assertCount(2, $scriptedResultPlatform->requests);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_last_round_that_only_reads_is_still_a_cut_short_answer(): void
    {
        $toolCallCounter = new ToolCallCounter();
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('lookup'),
        ]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry($toolCallCounter), 2);

        self::assertSame('max_tool_iterations', $llmResponse->stopReason());
        self::assertTrue($llmResponse->isDegraded());
        self::assertSame(0, $toolCallCounter->calls);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_last_round_that_answers_in_text_is_the_models_answer(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            new MultiPartResult([new TextResult('[]')]),
        ]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry(new ToolCallCounter()), 2);

        self::assertSame('[]', $llmResponse->content());
        self::assertFalse($llmResponse->isDegraded());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_only_the_tool_result_before_the_last_request_carries_the_notice(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('lookup'),
            $this->callOf('record'),
        ]);

        $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry(new ToolCallCounter()), 3);

        self::assertSame(
            ['usr', 'a file', FinalRound::announcedIn('a file')],
            [$this->lastText($scriptedResultPlatform, 0), $this->lastText($scriptedResultPlatform, 1), $this->lastText($scriptedResultPlatform, 2)],
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_conversation_that_ends_before_its_last_round_never_sees_the_notice(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            new MultiPartResult([new TextResult('done')]),
        ]);

        $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry(new ToolCallCounter()), 5);

        self::assertSame([], $this->requestsCarryingTheNotice($scriptedResultPlatform));
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_single_round_budget_has_no_tool_result_to_carry_the_notice_yet_a_recording_round_still_concludes(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([$this->callOf('record')]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry(new ToolCallCounter()), 1);

        self::assertSame([[], 'end_turn'], [$this->requestsCarryingTheNotice($scriptedResultPlatform), $llmResponse->stopReason()]);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_only_the_last_tool_result_of_a_round_with_several_calls_carries_the_notice(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup', 'lookup'),
            $this->callOf('record'),
        ]);

        $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry(new ToolCallCounter()), 2);

        $results = array_map(
            static fn (MessageInterface $message): ?string => $message instanceof ToolCallMessage ? $message->asText() : null,
            \array_slice($scriptedResultPlatform->requests[1], -2),
        );
        self::assertSame(['a file', FinalRound::announcedIn('a file')], $results);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_the_last_request_offers_the_same_tools_as_the_first_so_the_providers_prompt_cache_is_kept(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('record'),
        ]);

        $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->registry(new ToolCallCounter()), 2);

        self::assertNotEmpty($scriptedResultPlatform->options[0]['tools']);
        self::assertEquals($scriptedResultPlatform->options[0]['tools'], $scriptedResultPlatform->options[1]['tools']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_a_concurrent_window_ends_each_conversation_on_its_own_last_round(): void
    {
        $recordingCounter = new ToolCallCounter();
        $readingCounter = new ToolCallCounter();
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('lookup'),
            $this->callOf('record'),
            $this->callOf('lookup'),
        ]);

        $responses = $this->client($scriptedResultPlatform)->completeBatchWithTools([
            ['system' => 's', 'user' => 'recording', 'tools' => $this->registry($recordingCounter)],
            ['system' => 's', 'user' => 'reading', 'tools' => $this->registry($readingCounter)],
        ], 4, 2);

        self::assertSame(['end_turn', 'max_tool_iterations'], [$responses[0]->stopReason(), $responses[1]->stopReason()]);
        self::assertSame([1, 0], [$recordingCounter->calls, $readingCounter->calls]);
        self::assertCount(4, $scriptedResultPlatform->requests);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_a_concurrent_window_carries_the_notice_only_into_the_last_round(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('lookup'),
            $this->callOf('record'),
            $this->callOf('record'),
        ]);

        $this->client($scriptedResultPlatform)->completeBatchWithTools([
            ['system' => 's', 'user' => 'first', 'tools' => $this->registry(new ToolCallCounter())],
            ['system' => 's', 'user' => 'second', 'tools' => $this->registry(new ToolCallCounter())],
        ], 4, 2);

        self::assertSame(
            ['first', 'second', FinalRound::announcedIn('a file'), FinalRound::announcedIn('a file')],
            array_map(fn (int $request): ?string => $this->lastText($scriptedResultPlatform, $request), [0, 1, 2, 3]),
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_a_concurrent_round_that_records_before_the_last_one_does_not_end_the_conversation(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('record'),
            new MultiPartResult([new TextResult('done')]),
        ]);

        $responses = $this->client($scriptedResultPlatform)->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $this->registry(new ToolCallCounter())],
        ], 4, 3);

        self::assertSame('done', $responses[0]->content());
        self::assertCount(2, $scriptedResultPlatform->requests);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_last_round_whose_recording_call_is_refused_is_a_cut_short_answer(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('refuse'),
        ]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->refusingRegistry(), 2);

        self::assertSame('max_tool_iterations', $llmResponse->stopReason());
        self::assertTrue($llmResponse->isDegraded());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_last_round_where_one_recording_call_is_refused_and_another_recorded_still_ends_the_conversation(): void
    {
        $toolCallCounter = new ToolCallCounter();
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('refuse', 'record'),
        ]);

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $this->refusingRegistry($toolCallCounter), 2);

        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertSame(1, $toolCallCounter->calls);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_a_last_round_that_reads_is_not_concluded_whatever_its_tool_answers(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('lookup'),
        ]);
        $toolRegistry = new ToolRegistry([new FixedResultTool('lookup', RecordingToolInterface::RECORDED)], new NullLogger());

        $llmResponse = $this->client($scriptedResultPlatform)->completeWithTools('sys', 'usr', $toolRegistry, 2);

        self::assertSame('max_tool_iterations', $llmResponse->stopReason());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_a_concurrent_last_round_whose_recording_call_is_refused_is_a_cut_short_answer(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('refuse'),
        ]);

        $responses = $this->client($scriptedResultPlatform)->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $this->refusingRegistry()],
        ], 4, 2);

        self::assertSame('max_tool_iterations', $responses[0]->stopReason());
        self::assertTrue($responses[0]->isDegraded());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_a_concurrent_last_round_where_one_recording_call_is_refused_and_another_recorded_still_ends_the_conversation(): void
    {
        $toolCallCounter = new ToolCallCounter();
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('lookup'),
            $this->callOf('refuse', 'record'),
        ]);

        $responses = $this->client($scriptedResultPlatform)->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $this->refusingRegistry($toolCallCounter)],
        ], 4, 2);

        self::assertSame('end_turn', $responses[0]->stopReason());
        self::assertSame(1, $toolCallCounter->calls);
    }

    private function client(ScriptedResultPlatform $scriptedResultPlatform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(new PlatformBinding($scriptedResultPlatform, 'm', new NullLogger()));
    }

    /**
     * @throws InvalidToolRegistryException
     */
    private function registry(ToolCallCounter $toolCallCounter): ToolRegistry
    {
        return new ToolRegistry([
            new FixedResultTool('lookup', 'a file'),
            new CountingRecordingTool('record', $toolCallCounter),
        ], new NullLogger());
    }

    /**
     * @throws InvalidToolRegistryException
     */
    private function refusingRegistry(?ToolCallCounter $toolCallCounter = null): ToolRegistry
    {
        return new ToolRegistry([
            new FixedResultTool('lookup', 'a file'),
            new RefusingRecordingTool('refuse'),
            new CountingRecordingTool('record', $toolCallCounter ?? new ToolCallCounter()),
        ], new NullLogger());
    }

    private function callOf(string ...$toolNames): ResultInterface
    {
        $toolCalls = [];
        foreach (array_values($toolNames) as $position => $name) {
            $toolCalls[] = new ToolCall((string) $position, $name);
        }

        return new MultiPartResult([new ToolCallResult($toolCalls)]);
    }

    private function lastText(ScriptedResultPlatform $scriptedResultPlatform, int $request): ?string
    {
        $messages = $scriptedResultPlatform->requests[$request];
        $message = end($messages);

        return $message instanceof UserMessage || $message instanceof ToolCallMessage ? $message->asText() : null;
    }

    /**
     * @return list<int> the requests holding the notice in any message
     */
    private function requestsCarryingTheNotice(ScriptedResultPlatform $scriptedResultPlatform): array
    {
        return array_keys(array_filter($scriptedResultPlatform->requests, $this->carriesTheNotice(...)));
    }

    /**
     * @param iterable<object> $messages
     */
    private function carriesTheNotice(iterable $messages): bool
    {
        foreach ($messages as $message) {
            if (($message instanceof UserMessage || $message instanceof ToolCallMessage) && str_contains((string) $message->asText(), FinalRound::NOTICE)) {
                return true;
            }
        }

        return false;
    }
}
