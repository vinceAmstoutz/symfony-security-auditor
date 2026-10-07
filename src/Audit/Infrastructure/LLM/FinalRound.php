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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Result\ToolCall;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * The last round a tool-using conversation is allowed: the model is told it is
 * the last, and a round that records its answer ends the conversation instead
 * of asking for one more round to say it is done.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FinalRound
{
    public const string NOTICE = 'Tool rounds used up: this is your last answer, and nothing you read or search from now on reaches you. Do not call a reading or searching tool again. Record each finding you still hold with the recording tool, or give the final answer the instructions above ask for. With nothing to report, answer without calling a tool.';

    public static function isLast(int $round, int $maxToolIterations): bool
    {
        return $round === $maxToolIterations - 1;
    }

    /**
     * @return bool whether the round is the last one, in which case the notice now closes the conversation
     */
    public static function announceIn(MessageBag $messageBag, int $round, int $maxToolIterations): bool
    {
        if (!self::isLast($round, $maxToolIterations)) {
            return false;
        }

        $messageBag->add(Message::ofUser(self::NOTICE));

        return true;
    }

    public static function isConcludedBy(bool $isFinalRound, ToolRegistry $toolRegistry, ToolCall ...$toolCalls): bool
    {
        if (!$isFinalRound) {
            return false;
        }

        foreach ($toolCalls as $toolCall) {
            if ($toolRegistry->isRecording($toolCall->getName())) {
                return true;
            }
        }

        return false;
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public static function answer(string $model, TokenUsageSnapshot $tokenUsageSnapshot): LLMResponse
    {
        return LLMResponse::of('', $model, 'end_turn', $tokenUsageSnapshot);
    }
}
