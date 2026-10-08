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
use Symfony\AI\Platform\FinishReason\FinishReasonCase;
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
    public function __construct(
        private ?TokenUsageRecorder $tokenUsageRecorder,
        private LoggerInterface $logger = new NullLogger(),
    ) {}

    /** @return array{0: int, 1: int, 2: int, 3: int}
     *
     * @throws NegativeTokenCountException
     */
    public function extractTokens(DeferredResult $deferredResult): array
    {
        $metadata = $deferredResult->getMetadata()->all();
        $tokenUsage = $metadata['token_usage'] ?? null;
        if (!$tokenUsage instanceof TokenUsageInterface) {
            return [0, 0, 0, 0];
        }

        [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens] = $this->tokenCounts($tokenUsage);
        $this->assertNonNegative($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens);
        $this->tokenUsageRecorder?->record($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens);

        return [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens];
    }

    /**
     * The usage a provider reported in the raw answer of a call its bridge
     * failed to convert, read with that bridge's own extractor — a failed
     * conversion attaches no `token_usage` metadata. Null when the answer
     * reports none, cannot be read, or reports a negative count. Nothing is
     * recorded here: the caller books the failed call.
     */
    public function extractBilledUsage(DeferredResult $deferredResult): ?TokenUsageSnapshot
    {
        try {
            $tokenUsage = $deferredResult->getResultConverter()->getTokenUsageExtractor()?->extract($deferredResult->getRawResult());

            return $tokenUsage instanceof TokenUsageInterface ? TokenUsageSnapshot::of(...$this->tokenCounts($tokenUsage)) : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array{0: int, 1: int, 2: int, 3: int}
     */
    private function tokenCounts(TokenUsageInterface $tokenUsage): array
    {
        return [
            $tokenUsage->getPromptTokens() ?? 0,
            $tokenUsage->getCompletionTokens() ?? 0,
            $tokenUsage->getCacheReadTokens() ?? 0,
            $tokenUsage->getCacheCreationTokens() ?? 0,
        ];
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

        $this->warnWhenDegraded($finishReason);

        return $this->normalizedStopReason($finishReason);
    }

    /**
     * Truncation and content filtering come back as symfony/ai's case values
     * whatever the provider calls them (`max_tokens`, `MAX_TOKENS`, `length`,
     * …), so `LLMResponse::isDegraded()` recognizes them; every other reason
     * keeps the provider's own word.
     */
    private function normalizedStopReason(FinishReason $finishReason): string
    {
        return $finishReason->is(FinishReasonCase::LENGTH, FinishReasonCase::CONTENT_FILTER)
            ? $finishReason->getCase()->value
            : $finishReason->getRaw();
    }

    private function warnWhenDegraded(FinishReason $finishReason): void
    {
        $warning = match (true) {
            $finishReason->is(FinishReasonCase::LENGTH) => 'LLM response was truncated by the output token limit — findings may be lost; raise max_output_tokens (or the per-agent attacker/reviewer variants)',
            $finishReason->is(FinishReasonCase::CONTENT_FILTER) => 'LLM response was suppressed by the provider content filter — findings may be lost',
            default => null,
        };

        if (null !== $warning) {
            $this->logger->warning($warning, ['finish_reason' => $finishReason->getRaw()]);
        }
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
