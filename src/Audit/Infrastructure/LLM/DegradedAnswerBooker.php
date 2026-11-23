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
use Symfony\AI\Platform\Result\DeferredResult;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;

/**
 * Books a failed call the provider answered (and billed) on the budget, the
 * token totals and the rate-limit window: at the usage its raw answer
 * reports, else at its estimated input tokens and no output. A call the
 * provider never answered only releases its rate-limit reservation; one cut
 * mid-answer is counted as interrupted.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class DegradedAnswerBooker
{
    public function __construct(
        private string $model,
        private ?BudgetTracker $budgetTracker,
        private LoggerInterface $logger,
        private RateLimiterInterface $rateLimiter,
        private TransientFailureClassifier $transientFailureClassifier,
        private PlatformResultExtractor $platformResultExtractor,
        private ?TokenUsageRecorder $tokenUsageRecorder = null,
    ) {}

    /**
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    public function bookFailedCall(Throwable $throwable, ?DeferredResult $deferredResult, int $estimatedInputTokens): void
    {
        if ($this->transientFailureClassifier->isCutMidAnswer($throwable)) {
            $this->budgetTracker?->recordInterruptedCall();
        }

        $stopReason = $this->transientFailureClassifier->billedStopReason($throwable);
        if (null === $stopReason) {
            $this->rateLimiter->record(0, 0);

            return;
        }

        $reportedUsage = $deferredResult instanceof DeferredResult ? $this->platformResultExtractor->extractBilledUsage($deferredResult, $estimatedInputTokens) : null;
        $billedUsage = $reportedUsage ?? TokenUsageSnapshot::of($estimatedInputTokens, 0);

        $this->rateLimiter->record($this->rateLimitedInputTokens($deferredResult, $billedUsage), $billedUsage->outputTokens());
        $this->budgetTracker?->recordCall(LLMResponse::of('', $this->model, $stopReason, $billedUsage), $this->oneHourCacheCreationTokens($deferredResult, $billedUsage));
        $this->tokenUsageRecorder?->record($billedUsage->inputTokens(), $billedUsage->outputTokens(), $billedUsage->cacheReadTokens(), $billedUsage->cacheCreationTokens());
        $this->logBooking($stopReason, $reportedUsage, $estimatedInputTokens);
    }

    private function oneHourCacheCreationTokens(?DeferredResult $deferredResult, TokenUsageSnapshot $tokenUsageSnapshot): int
    {
        return $deferredResult instanceof DeferredResult
            ? $this->platformResultExtractor->extractOneHourCacheCreationTokens($deferredResult, $tokenUsageSnapshot->cacheCreationTokens())
            : 0;
    }

    private function rateLimitedInputTokens(?DeferredResult $deferredResult, TokenUsageSnapshot $tokenUsageSnapshot): int
    {
        return $deferredResult instanceof DeferredResult ? $this->platformResultExtractor->rateLimitedInputTokens($deferredResult, $tokenUsageSnapshot) : $tokenUsageSnapshot->inputTokens();
    }

    private function logBooking(string $stopReason, ?TokenUsageSnapshot $tokenUsageSnapshot, int $estimatedInputTokens): void
    {
        if ($tokenUsageSnapshot instanceof TokenUsageSnapshot) {
            $this->logger->debug('An answer the provider delivered as an error is booked at the usage it reported, since the provider bills the request it accepted', [
                'stop_reason' => $stopReason,
                'input_tokens' => $tokenUsageSnapshot->inputTokens(),
                'output_tokens' => $tokenUsageSnapshot->outputTokens(),
            ]);

            return;
        }

        $this->logger->debug('An answer the provider delivered as an error is booked at its estimated input tokens, since the provider bills the request it accepted', [
            'stop_reason' => $stopReason,
            'estimated_input_tokens' => $estimatedInputTokens,
        ]);
    }
}
