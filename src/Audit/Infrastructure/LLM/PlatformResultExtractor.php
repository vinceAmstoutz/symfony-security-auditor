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
use Symfony\AI\Platform\TokenUsage\TokenUsageInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;

/**
 * Extracts token usage, tool calls, text, and the provider finish reason from
 * symfony/ai platform results, recording usage on the optional telemetry
 * recorder and warning when a response was truncated or content-filtered.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformResultExtractor
{
    private FinishReasonReader $finishReasonReader;

    public function __construct(
        private ?TokenUsageRecorder $tokenUsageRecorder,
        private LoggerInterface $logger = new NullLogger(),
    ) {
        $this->finishReasonReader = new FinishReasonReader($logger);
    }

    /**
     * The usage the provider reported for an answered call, or, when it
     * reported none (Bedrock's InvokeModel route, a gateway that omits
     * `usage`), the call's estimated input tokens, which the provider bills
     * all the same: the output it produced is then unknown and counted as
     * none. A usage object that reports no prompt tokens (empty, or zero with
     * no cache count to account for the prompt) books the estimate for the
     * input as well, beside the completion it reported.
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
     * A request is never empty, so a prompt count that is missing, or zero
     * with no cache read or write to stand in for it (Anthropic counts those
     * apart from its input tokens), is a provider that did not report it.
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
     * The usage a provider reported in the raw answer of a call its bridge
     * failed to convert, read with that bridge's own extractor — a failed
     * conversion attaches no `token_usage` metadata. A usage that reports no
     * prompt tokens has the call's estimated input tokens as its input, as in
     * `extractTokens()`. Null when the answer reports none, cannot be read, or
     * reports a negative count. Nothing is recorded here: the caller books the
     * failed call.
     */
    public function extractBilledUsage(DeferredResult $deferredResult, int $estimatedInputTokens): ?TokenUsageSnapshot
    {
        try {
            $tokenUsage = $deferredResult->getResultConverter()->getTokenUsageExtractor()?->extract($deferredResult->getRawResult());

            return $tokenUsage instanceof TokenUsageInterface ? TokenUsageSnapshot::of(...$this->billedTokenCounts($tokenUsage, $estimatedInputTokens)) : null;
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
        $cachedInsidePrompt = $this->cachedTokensInsidePrompt($tokenUsage, $promptTokens);

        return [
            $promptTokens - $cachedInsidePrompt,
            $completionTokens + $this->thinkingTokensCountedApart($tokenUsage, $promptTokens, $completionTokens),
            0 === $cachedInsidePrompt ? $tokenUsage->getCacheReadTokens() ?? 0 : $cachedInsidePrompt,
            $tokenUsage->getCacheCreationTokens() ?? 0,
        ];
    }

    /**
     * Anthropic counts cache reads and writes apart from its input tokens and
     * always reports the writes; OpenAI-style providers (OpenAI, Gemini,
     * DeepSeek, gateways) report a total and count the cached tokens inside
     * the prompt. Booking both as they come would bill the cached share twice
     * at the full input rate, or never at the cache rate.
     */
    private function cachedTokensInsidePrompt(TokenUsageInterface $tokenUsage, int $promptTokens): int
    {
        if (null !== $tokenUsage->getCacheCreationTokens() || null === $tokenUsage->getTotalTokens()) {
            return 0;
        }

        $cachedTokens = $tokenUsage->getCacheReadTokens() ?? $tokenUsage->getCachedTokens() ?? 0;

        return $cachedTokens <= $promptTokens ? $cachedTokens : 0;
    }

    /**
     * Gemini and Vertex AI bill their thought tokens as output yet report
     * them apart from the candidates, so the total is the sum of the three;
     * OpenAI-style providers count their reasoning tokens inside the
     * completion, so adding them would bill the same tokens twice. Only a
     * total that has room for the thinking tokens next to the prompt and the
     * completion shows they were counted apart.
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
     * The share of the `$cacheCreationTokens` cache writes a call is booked
     * with that Anthropic keeps for an hour (`cache_retention: long`) and
     * bills at its own rate. Only the raw answer reports it: the bridge's
     * usage counts every write alike. None when the answer does not split its
     * writes or cannot be read.
     */
    public function extractOneHourCacheCreationTokens(DeferredResult $deferredResult, int $cacheCreationTokens): int
    {
        try {
            $usage = $deferredResult->getRawResult()->getData()['usage'] ?? null;
        } catch (Throwable) {
            return 0;
        }

        $cacheCreation = \is_array($usage) ? $usage['cache_creation'] ?? null : null;
        $oneHourCacheCreationTokens = \is_array($cacheCreation) ? $cacheCreation['ephemeral_1h_input_tokens'] ?? null : null;

        return \is_int($oneHourCacheCreationTokens) ? min($oneHourCacheCreationTokens, $cacheCreationTokens) : 0;
    }

    /**
     * The model the provider says served the call, which a gateway routing
     * on its own, or a failover platform, can differ from the one requested.
     */
    public function extractReportedModel(DeferredResult $deferredResult): ?string
    {
        $tokenUsage = $deferredResult->getMetadata()->all()['token_usage'] ?? null;
        $reportedModel = $tokenUsage instanceof TokenUsageInterface ? $tokenUsage->getModel() : null;

        return '' === $reportedModel ? null : $reportedModel;
    }

    /**
     * A negative count here is a compromised or malfunctioning provider
     * response — every caller relies on rejecting it before it ever reaches
     * `RateLimiterInterface::record()`, whose mutable window counters have no
     * lower bound of their own and would stay corrupted for the rest of the
     * rate-limit window. `$tokenUsageRecorder` is optional
     * ({@see PlatformAccountingConfig}
     * defaults it to `null`), so this guard cannot live behind it — it must
     * run unconditionally.
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

    public function extractStopReason(DeferredResult $deferredResult): ?string
    {
        $finishReason = $deferredResult->getMetadata()->all()['finish_reason'] ?? null;
        if (!$finishReason instanceof FinishReason) {
            return null;
        }

        return $this->finishReasonReader->stopReason($finishReason, $this->extractText($deferredResult->getResult()));
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
     * The model's answer as the assistant turn that goes back with the tool
     * results: whole, so a signed thinking block and the text in between its
     * tool calls come back the way the provider produced them.
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
