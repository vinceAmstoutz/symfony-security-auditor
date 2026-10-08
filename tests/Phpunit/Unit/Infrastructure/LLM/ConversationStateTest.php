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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ConversationState;

final class ConversationStateTest extends TestCase
{
    /**
     * @throws InvalidTokenUsageException
     */
    public function test_a_window_whose_every_conversation_has_its_answer_is_all_answered(): void
    {
        self::assertTrue(ConversationState::allAnswered([$this->answered(), $this->answered()]));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_one_conversation_still_waiting_keeps_the_window_open(): void
    {
        self::assertFalse(ConversationState::allAnswered([$this->answered(), $this->state(null)]));
    }

    public function test_a_window_with_no_conversation_left_is_all_answered(): void
    {
        self::assertTrue(ConversationState::allAnswered([]));
    }

    public function test_a_started_conversation_has_run_no_tool_and_recorded_nothing(): void
    {
        $messageBag = new MessageBag(Message::ofUser('u'));

        $conversationState = ConversationState::start($messageBag, ['tools' => []], 42);

        self::assertSame($messageBag, $conversationState->bag);
        self::assertSame(['tools' => []], $conversationState->options);
        self::assertSame(42, $conversationState->estimatedInputTokens);
        self::assertSame([0, 0, 0, 0], [$conversationState->input, $conversationState->output, $conversationState->cacheRead, $conversationState->cacheCreation]);
        self::assertFalse($conversationState->toolsRan);
        self::assertNull($conversationState->response);
        self::assertSame(0, $conversationState->roundsLeft);
    }

    public function test_entering_a_round_tells_every_conversation_how_many_rounds_it_has_left_itself_included(): void
    {
        $entered = ConversationState::enterRound([3 => $this->state(null), 7 => $this->state(null)], 2, 5);

        self::assertSame([3 => 3, 7 => 3], array_map(static fn (ConversationState $conversationState): int => $conversationState->roundsLeft, $entered));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_the_rounds_left_survive_every_transition_of_a_conversation(): void
    {
        $entered = ConversationState::enterRound([$this->state(null)], 1, 4)[0];

        $conversationState = $entered->withRecordedTokens(1, 1, 1, 1)->withExecutedTools(10)->withResponse(LLMResponse::of('done', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));

        self::assertSame(3, $conversationState->roundsLeft);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_reports_the_tokens_recorded_across_rounds_as_a_usage_snapshot(): void
    {
        $tokenUsageSnapshot = $this->state(null)->withRecordedTokens(10, 5, 3, 2)->withRecordedTokens(1, 1, 1, 1)->tokenUsage();

        self::assertSame([11, 6, 4, 3], [$tokenUsageSnapshot->inputTokens(), $tokenUsageSnapshot->outputTokens(), $tokenUsageSnapshot->cacheReadTokens(), $tokenUsageSnapshot->cacheCreationTokens()]);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function answered(): ConversationState
    {
        return $this->state(LLMResponse::of('done', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
    }

    private function state(?LLMResponse $llmResponse): ConversationState
    {
        return new ConversationState(new MessageBag(Message::ofUser('u')), [], 0, 0, 0, 0, false, $llmResponse, 1);
    }
}
