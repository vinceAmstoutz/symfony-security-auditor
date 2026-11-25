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

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\Message\AssistantMessage;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsageInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;

/**
 * Reads the usage, tool calls, text and finish reason of a platform result,
 * recording the usage on the telemetry recorder.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PlatformResultExtractor
{
    private const string END_TURN_STOP_REASON = 'end_turn';

    private const string EMPTY_CONTENT_STOP_REASON = 'empty_content';

    private FinishReasonReader $finishReasonReader;

    public function __construct(
        private ?TokenUsageRecorder $tokenUsageRecorder,
        private LoggerInterface $logger = new NullLogger(),
    ) {
        $this->finishReasonReader = new FinishReasonReader($logger);
    }

    /**
     * Returns the usage the provider reported, or the estimated input tokens
     * and no output when it reported none. A usage that reports no prompt
     * tokens takes the estimate as its input.
     *
     * @return array{0: int, 1: int, 2: int, 3: int}
     *
     * @throws NegativeTokenCountException
     */
    public function extractTokens(DeferredResult $deferredResult, int $estimatedInputTokens): array
    {
        $metadata = $deferredResult->getMetadata()->all();
        $tokenUsage = $metadata['token_usage'] ?? null;
        if (!$tokenUsage instanceof TokenUsageInterface) {
            return $this->bookEstimatedInput($estimatedInputTokens);
        }

        [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens] = $this->billedTokenCounts($tokenUsage, $estimatedInputTokens);
        $this->assertNonNegative($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens);
        $this->tokenUsageRecorder?->record($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens);

        return [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens];
    }

    /**
     * @return array{0: int, 1: int, 2: int, 3: int}
     */
    private function billedTokenCounts(TokenUsageInterface $tokenUsage, int $estimatedInputTokens): array
    {
        [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens] = $this->tokenCounts($tokenUsage);
        if (!$this->reportsPrompt($tokenUsage, $inputTokens, $cacheReadTokens, $cacheCreationTokens)) {
            $this->logger->debug('The provider reported no prompt tokens for an answer; its input is booked at the estimated input tokens, since the provider bills the request it accepted', [
                'estimated_input_tokens' => $estimatedInputTokens,
            ]);
            $inputTokens = $estimatedInputTokens;
        }

        return [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens];
    }

    /**
     * Returns false for a prompt count that is missing, or zero with no cache
     * read or write to account for the prompt.
     */
    private function reportsPrompt(TokenUsageInterface $tokenUsage, int $inputTokens, int $cacheReadTokens, int $cacheCreationTokens): bool
    {
        return null !== $tokenUsage->getPromptTokens() && (0 !== $inputTokens || 0 !== $cacheReadTokens || 0 !== $cacheCreationTokens);
    }

    /**
     * @return array{0: int, 1: int, 2: int, 3: int}
     *
     * @throws NegativeTokenCountException
     */
    private function bookEstimatedInput(int $estimatedInputTokens): array
    {
        $this->logger->debug('The provider reported no token usage for an answer; it is booked at its estimated input tokens, since the provider bills the request it accepted', [
            'estimated_input_tokens' => $estimatedInputTokens,
        ]);
        $this->tokenUsageRecorder?->record($estimatedInputTokens, 0, 0, 0);

        return [$estimatedInputTokens, 0, 0, 0];
    }

    /**
     * Returns the usage reported in the raw answer of a call the bridge failed
     * to convert, its input read as in `extractTokens()`; null when the answer
     * reports none, cannot be read or reports a negative count. Records
     * nothing: the caller books the failed call.
     */
    public function extractBilledUsage(DeferredResult $deferredResult, int $estimatedInputTokens): ?TokenUsageSnapshot
    {
        try {
            $tokenUsage = $this->usageInRawAnswer($deferredResult);

            return $tokenUsage instanceof TokenUsageInterface ? TokenUsageSnapshot::of(...$this->billedTokenCounts($tokenUsage, $estimatedInputTokens)) : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Returns the input tokens the provider counts against its per-minute
     * input limit: the input and the cache writes, plus the cache reads where
     * the provider counts them inside its prompt (OpenAI-style providers, not
     * Anthropic).
     */
    public function rateLimitedInputTokens(DeferredResult $deferredResult, TokenUsageSnapshot $tokenUsageSnapshot): int
    {
        $cacheReadsCountedInPrompt = $this->countsCacheReadsInPrompt($this->reportedUsage($deferredResult));

        return $tokenUsageSnapshot->inputTokens() + $tokenUsageSnapshot->cacheCreationTokens() + ($cacheReadsCountedInPrompt ? $tokenUsageSnapshot->cacheReadTokens() : 0);
    }

    /**
     * Returns false for a usage with no prompt count, whose input is booked at
     * an estimate that already holds the cached share.
     */
    private function countsCacheReadsInPrompt(TokenUsageInterface $tokenUsage): bool
    {
        $promptTokens = $tokenUsage->getPromptTokens();

        return null !== $promptTokens && null !== $this->cacheCountedInsidePrompt($tokenUsage, $promptTokens);
    }

    /**
     * Returns the usage of the call, read from its raw answer when the bridge
     * failed to convert it; an empty usage when it reports none.
     */
    private function reportedUsage(DeferredResult $deferredResult): TokenUsageInterface
    {
        $tokenUsage = $deferredResult->getMetadata()->all()['token_usage'] ?? null;

        return $tokenUsage instanceof TokenUsageInterface ? $tokenUsage : $this->usageInRawAnswer($deferredResult) ?? new TokenUsage();
    }

    private function usageInRawAnswer(DeferredResult $deferredResult): ?TokenUsageInterface
    {
        $tokenUsageExtractor = $deferredResult->getResultConverter()->getTokenUsageExtractor();

        return $tokenUsageExtractor instanceof TokenUsageExtractorInterface ? $this->extractedUsage($tokenUsageExtractor, $deferredResult) : null;
    }

    private function extractedUsage(TokenUsageExtractorInterface $tokenUsageExtractor, DeferredResult $deferredResult): ?TokenUsageInterface
    {
        try {
            return $tokenUsageExtractor->extract($deferredResult->getRawResult());
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array{0: int, 1: int, 2: int, 3: int}
     */
    private function tokenCounts(TokenUsageInterface $tokenUsage): array
    {
        $promptTokens = $tokenUsage->getPromptTokens() ?? 0;
        $completionTokens = $tokenUsage->getCompletionTokens() ?? 0;
        $outputTokens = $completionTokens + $this->thinkingTokensCountedApart($tokenUsage, $promptTokens, $completionTokens);
        $cacheInsidePrompt = $this->cacheCountedInsidePrompt($tokenUsage, $promptTokens);
        if (null === $cacheInsidePrompt) {
            return [$promptTokens, $outputTokens, $tokenUsage->getCacheReadTokens() ?? 0, $tokenUsage->getCacheCreationTokens() ?? 0];
        }

        [$cacheReadTokens, $cacheCreationTokens] = $cacheInsidePrompt;

        return [$promptTokens - $cacheReadTokens - $cacheCreationTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens];
    }

    /**
     * Returns the cache reads and writes an OpenAI-style provider counts
     * inside the prompt, so the cached share is not billed twice; null when
     * the cache is counted apart from the prompt, as Anthropic does.
     *
     * @return array{0: int, 1: int}|null the cache reads and writes inside the prompt
     */
    private function cacheCountedInsidePrompt(TokenUsageInterface $tokenUsage, int $promptTokens): ?array
    {
        $totalTokens = $tokenUsage->getTotalTokens();
        if (null === $totalTokens) {
            return null;
        }

        $cacheReadTokens = $tokenUsage->getCacheReadTokens() ?? $tokenUsage->getCachedTokens() ?? 0;
        $cacheCreationTokens = $tokenUsage->getCacheCreationTokens();
        if (null !== $cacheCreationTokens && $promptTokens + ($tokenUsage->getCompletionTokens() ?? 0) + $cacheReadTokens + $cacheCreationTokens <= $totalTokens) {
            return null;
        }

        $cacheCreationTokens ??= 0;

        return $cacheReadTokens + $cacheCreationTokens <= $promptTokens ? [$cacheReadTokens, $cacheCreationTokens] : null;
    }

    /**
     * Returns the thinking tokens reported apart from the completion (Gemini,
     * Vertex AI), which only a total with room for them shows; zero when the
     * completion holds them, as OpenAI-style providers count them.
     */
    private function thinkingTokensCountedApart(TokenUsageInterface $tokenUsage, int $promptTokens, int $completionTokens): int
    {
        $thinkingTokens = $tokenUsage->getThinkingTokens() ?? 0;
        $totalTokens = $tokenUsage->getTotalTokens();

        if (null === $totalTokens || $promptTokens + $completionTokens + $thinkingTokens > $totalTokens) {
            return 0;
        }

        return $thinkingTokens;
    }

    /**
     * Returns the share of `$cacheCreationTokens` that Anthropic keeps for an
     * hour and bills at its own rate, read from the raw answer; zero when the
     * answer does not split its writes or cannot be read.
     */
    public function extractOneHourCacheCreationTokens(DeferredResult $deferredResult, int $cacheCreationTokens): int
    {
        return min(ReportedUsages::oneHourCacheCreationTokens($deferredResult->getRawResult()), $cacheCreationTokens);
    }

    /**
     * Returns the model the provider says served the call, which a gateway or
     * a failover platform can change.
     */
    public function extractReportedModel(DeferredResult $deferredResult): ?string
    {
        $tokenUsage = $deferredResult->getMetadata()->all()['token_usage'] ?? null;
        $reportedModel = $tokenUsage instanceof TokenUsageInterface ? $tokenUsage->getModel() : null;

        return '' === $reportedModel ? null : $reportedModel;
    }

    /**
     * Rejects a negative count before it reaches
     * `RateLimiterInterface::record()`, whose window counters have no lower
     * bound, whether or not a telemetry recorder is set.
     *
     * @throws NegativeTokenCountException
     */
    private function assertNonNegative(int $inputTokens, int $outputTokens, int $cacheReadTokens, int $cacheCreationTokens): void
    {
        if ($inputTokens < 0) {
            throw NegativeTokenCountException::forInputTokens($inputTokens);
        }

        if ($outputTokens < 0) {
            throw NegativeTokenCountException::forOutputTokens($outputTokens);
        }

        if ($cacheReadTokens < 0) {
            throw NegativeTokenCountException::forCacheReadTokens($cacheReadTokens);
        }

        if ($cacheCreationTokens < 0) {
            throw NegativeTokenCountException::forCacheCreationTokens($cacheCreationTokens);
        }
    }

    /**
     * Returns `empty_content`, never a verdict, for an answer that carries
     * no finish reason and is neither text nor tool calls, such as a stream
     * a platform handed back unread.
     */
    public function extractStopReason(DeferredResult $deferredResult): string
    {
        $finishReason = $deferredResult->getMetadata()->all()['finish_reason'] ?? null;
        if (!$finishReason instanceof FinishReason) {
            return $this->isReadable($deferredResult->getResult()) ? self::END_TURN_STOP_REASON : self::EMPTY_CONTENT_STOP_REASON;
        }

        return $this->finishReasonReader->stopReason($finishReason, $this->extractText($deferredResult->getResult()));
    }

    private function isReadable(ResultInterface $result): bool
    {
        return $result instanceof TextResult || $result instanceof ToolCallResult || $result instanceof MultiPartResult;
    }

    /**
     * @return list<ToolCall>
     */
    public function extractToolCalls(ResultInterface $result): array
    {
        if ($result instanceof ToolCallResult) {
            return array_values($result->getContent());
        }

        if ($result instanceof MultiPartResult) {
            $toolCalls = [];
            foreach ($result->getContent() as $part) {
                if ($part instanceof ToolCallResult) {
                    array_push($toolCalls, ...$part->getContent());
                }
            }

            return $toolCalls;
        }

        return [];
    }

    /**
     * Returns the whole answer as the assistant turn sent back with the tool
     * results, so a signed thinking block returns as the provider wrote it.
     */
    public function extractAssistantMessage(ResultInterface $result): AssistantMessage
    {
        return Message::ofAssistant($result);
    }

    public function extractText(ResultInterface $result): string
    {
        if ($result instanceof TextResult) {
            return $result->getContent();
        }

        if ($result instanceof MultiPartResult) {
            return $result->asText();
        }

        return '';
    }
}
