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
 * The last round a tool conversation is allowed. The tool result before it
 * carries the notice, since a provider may refuse a user turn right after a
 * tool result. A last round whose recording tool takes a call in concludes
 * the conversation; one that asks to read gets one closing request, its
 * reading calls answered `NOT_RUN`. The answer of a model that called a
 * reading tool is marked as reaching the tool cap; one that only recorded is
 * not.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FinalRound
{
    public const string NOT_RUN = '[Auditor notice: round limit reached, not run. Record what you still hold with the recording tool, or give the final answer the instructions above ask for.]';

    public const string NOTICE = '[Auditor notice: the next round is your last. Nothing you read or search after this reaches you, so do not call a reading or searching tool again. Record each finding you still hold with the recording tool, or give the final answer the instructions above ask for. With nothing to report, answer without calling a tool.]';

    private static function isFinal(int $roundsLeft): bool
    {
        return $roundsLeft <= 1;
    }

    public static function carried(string $toolResult, int $roundsLeft, bool $isLastResult): string
    {
        return 2 === $roundsLeft && $isLastResult ? self::announcedIn($toolResult) : $toolResult;
    }

    public static function announcedIn(string $toolResult): string
    {
        return \sprintf("%s\n\n%s", $toolResult, self::NOTICE);
    }

    public static function resultOf(ToolRegistry $toolRegistry, ToolCall $toolCall, int $roundsLeft): string
    {
        if (self::isFinal($roundsLeft) && !$toolRegistry->isRecording($toolCall->getName())) {
            return self::NOT_RUN;
        }

        return $toolRegistry->execute($toolCall->getName(), $toolCall->getArguments());
    }

    /**
     * @param list<ToolCall> $toolCalls
     * @param list<string>   $toolResults the answer to each call, in the same order
     */
    public static function isConcludedBy(int $roundsLeft, ToolRegistry $toolRegistry, array $toolCalls, array $toolResults): bool
    {
        if (!self::isFinal($roundsLeft)) {
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
     * @param list<ToolCall> $toolCalls
     */
    public static function asksToRead(ToolRegistry $toolRegistry, array $toolCalls): bool
    {
        foreach ($toolCalls as $toolCall) {
            if (!$toolRegistry->isRecording($toolCall->getName())) {
                return true;
            }
        }

        return false;
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public static function answer(string $model, TokenUsageSnapshot $tokenUsageSnapshot, bool $askedToRead): LLMResponse
    {
        $llmResponse = LLMResponse::of('', $model, 'end_turn', $tokenUsageSnapshot);

        return $askedToRead ? $llmResponse->withReachedToolCap() : $llmResponse;
    }

    public static function settled(LLMResponse $llmResponse, int $roundsLeft, bool $askedToRead): LLMResponse
    {
        return self::isFinal($roundsLeft) && $askedToRead ? $llmResponse->withReachedToolCap() : $llmResponse;
    }
}
