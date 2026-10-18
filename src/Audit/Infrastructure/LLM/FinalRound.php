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
 * say it is done. A last round that asks to read instead gets one closing
 * request: its reading calls are answered without being run, since nothing
 * they return could reach a later round. An answer given on either by a model
 * that called a reading tool reached the round limit, so it may rest on less
 * than the model wanted to look at; one that only ever recorded lost nothing
 * to the limit.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
