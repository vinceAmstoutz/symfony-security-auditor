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
use Symfony\AI\Platform\Result\ToolCall;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\FinalRound;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CountingReadingTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CountingRecordingTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ToolCallCounter;

final class FinalRoundTest extends TestCase
{
    /**
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('finalRounds')]
    public function test_a_reading_call_of_a_final_round_is_answered_without_being_run(int $roundsLeft): void
    {
        $toolCallCounter = new ToolCallCounter();

        $result = FinalRound::resultOf($this->registry($toolCallCounter, new ToolCallCounter()), new ToolCall('1', 'read'), $roundsLeft);

        self::assertSame([FinalRound::NOT_RUN, 0], [$result, $toolCallCounter->calls]);
    }

    /**
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('finalRounds')]
    public function test_a_recording_call_of_a_final_round_is_run(int $roundsLeft): void
    {
        $toolCallCounter = new ToolCallCounter();

        $result = FinalRound::resultOf($this->registry(new ToolCallCounter(), $toolCallCounter), new ToolCall('1', 'record'), $roundsLeft);

        self::assertSame(['recorded', 1], [$result, $toolCallCounter->calls]);
    }

    /**
     * @throws InvalidToolRegistryException
     */
    public function test_a_reading_call_before_the_last_round_is_run(): void
    {
        $toolCallCounter = new ToolCallCounter();

        $result = FinalRound::resultOf($this->registry($toolCallCounter, new ToolCallCounter()), new ToolCall('1', 'read'), 2);

        self::assertSame(['a file', 1], [$result, $toolCallCounter->calls]);
    }

    /**
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('finalRounds')]
    public function test_a_recorded_call_concludes_a_final_round(int $roundsLeft): void
    {
        self::assertTrue(FinalRound::isConcludedBy($roundsLeft, $this->registry(new ToolCallCounter(), new ToolCallCounter()), [new ToolCall('1', 'record')], ['recorded']));
    }

    /**
     * @throws InvalidToolRegistryException
     */
    public function test_a_recorded_call_before_the_last_round_concludes_nothing(): void
    {
        self::assertFalse(FinalRound::isConcludedBy(2, $this->registry(new ToolCallCounter(), new ToolCallCounter()), [new ToolCall('1', 'record')], ['recorded']));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('finalRounds')]
    public function test_a_text_answer_on_a_final_round_after_asking_to_read_reached_the_round_limit(int $roundsLeft): void
    {
        self::assertTrue(FinalRound::settled($this->textAnswer(), $roundsLeft, true)->reachedToolCap());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_a_text_answer_before_the_last_round_did_not_reach_the_round_limit(): void
    {
        self::assertFalse(FinalRound::settled($this->textAnswer(), 2, true)->reachedToolCap());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_a_text_answer_on_a_final_round_without_asking_to_read_did_not_reach_the_round_limit(): void
    {
        self::assertFalse(FinalRound::settled($this->textAnswer(), 1, false)->reachedToolCap());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_the_answer_that_concludes_a_final_round_after_asking_to_read_reached_the_round_limit(): void
    {
        $llmResponse = FinalRound::answer('m', TokenUsageSnapshot::of(3, 2), true);

        self::assertSame(['', 'end_turn', true], [$llmResponse->content(), $llmResponse->stopReason(), $llmResponse->reachedToolCap()]);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_the_answer_that_concludes_a_final_round_without_asking_to_read_did_not_reach_the_round_limit(): void
    {
        $llmResponse = FinalRound::answer('m', TokenUsageSnapshot::of(3, 2), false);

        self::assertSame(['', 'end_turn', false], [$llmResponse->content(), $llmResponse->stopReason(), $llmResponse->reachedToolCap()]);
    }

    /**
     * @param list<string> $toolNames
     *
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('roundsOfCalls')]
    public function test_a_round_asks_to_read_when_one_of_its_calls_is_not_a_recording_one(array $toolNames, bool $asksToRead): void
    {
        $toolCalls = array_map(static fn (string $toolName): ToolCall => new ToolCall('1', $toolName), $toolNames);

        self::assertSame($asksToRead, FinalRound::asksToRead($this->registry(new ToolCallCounter(), new ToolCallCounter()), $toolCalls));
    }

    /**
     * @return iterable<string, array{list<string>, bool}>
     */
    public static function roundsOfCalls(): iterable
    {
        yield 'only recording calls' => [['record', 'record'], false];
        yield 'a reading call after a recording one' => [['record', 'read'], true];
        yield 'a reading call before a recording one' => [['read', 'record'], true];
        yield 'a call to a tool the registry does not hold' => [['record', 'unknown'], true];
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function finalRounds(): iterable
    {
        yield 'the last allowed round' => [1];
        yield 'the closing request after it' => [0];
    }

    /**
     * @throws InvalidToolRegistryException
     */
    private function registry(ToolCallCounter $readings, ToolCallCounter $records): ToolRegistry
    {
        return new ToolRegistry([new CountingReadingTool('read', $readings), new CountingRecordingTool('record', $records)], new NullLogger());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function textAnswer(): LLMResponse
    {
        return LLMResponse::of('[]', 'm', 'end_turn', TokenUsageSnapshot::of(3, 2));
    }
}
