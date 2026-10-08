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

use Symfony\AI\Platform\Result\ToolCall;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * The last round a tool-using conversation is allowed. The tool result that
 * precedes it carries a notice saying so — a tool result, not a message of its
 * own, because a provider may refuse a user turn right after one — and a last
 * round that records its answer (a recording tool took the call in, rather than
 * refusing it) ends the conversation instead of asking for one more round to
 * say it is done.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FinalRound
{
    public const string NOTICE = '[Auditor notice: the next round is your last. Nothing you read or search after this reaches you, so do not call a reading or searching tool again. Record each finding you still hold with the recording tool, or give the final answer the instructions above ask for. With nothing to report, answer without calling a tool.]';

    private static function isLast(int $roundsLeft): bool
    {
        return 1 === $roundsLeft;
    }

    public static function carried(string $toolResult, int $roundsLeft, bool $isLastResult): string
    {
        return 2 === $roundsLeft && $isLastResult ? self::announcedIn($toolResult) : $toolResult;
    }

    public static function announcedIn(string $toolResult): string
    {
        return \sprintf("%s\n\n%s", $toolResult, self::NOTICE);
    }

    /**
     * @param list<ToolCall> $toolCalls
     * @param list<string>   $toolResults the answer to each call, in the same order
     */
    public static function isConcludedBy(int $roundsLeft, ToolRegistry $toolRegistry, array $toolCalls, array $toolResults): bool
    {
        if (!self::isLast($roundsLeft)) {
            return false;
        }

        foreach ($toolCalls as $position => $toolCall) {
            if ($toolRegistry->isRecording($toolCall->getName()) && RecordingToolInterface::RECORDED === $toolResults[$position]) {
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
