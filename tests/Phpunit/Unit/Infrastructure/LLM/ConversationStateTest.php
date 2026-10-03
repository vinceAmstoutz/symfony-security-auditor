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
