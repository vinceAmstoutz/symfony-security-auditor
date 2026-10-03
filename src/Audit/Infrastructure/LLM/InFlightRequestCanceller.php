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
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;

/**
 * Winds down a concurrent request whose answer will never be read because a
 * sibling's failure ended the window. An HTTP response left unconsumed
 * completes itself in its destructor — it waits for the provider to finish
 * generating, then throws for a failed status in place of the failure already
 * propagating — so it is cancelled. Cancelling does not undo a request the
 * provider accepted and bills, so its estimated input tokens are booked as
 * spent; the output it would have produced is unknown and counted as none.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class InFlightRequestCanceller
{
    public function __construct(
        private string $model,
        private RateLimiterInterface $rateLimiter,
        private ?BudgetTracker $budgetTracker,
        private LoggerInterface $logger,
        private ?TokenUsageRecorder $tokenUsageRecorder = null,
    ) {}

    /**
     * The request whose own failure ended the window is cancelled but not
     * booked: its answer was read, or its fallback call recorded what it spent.
     * A request whose dispatch failed never reached the provider, so only the
     * rate-limit reservation taken for it is released.
     *
     * @param array<int, array{?DeferredResult, int}> $unconsumed each request the window has not consumed — its deferred result, null when its dispatch failed, and its estimated input tokens — by window index
     *
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    public function cancelAll(array $unconsumed, int $failedIndex): void
    {
        foreach ($unconsumed as $index => [$deferredResult, $estimatedInputTokens]) {
            if ($index === $failedIndex) {
                $this->cancel($deferredResult);

                continue;
            }

            if (!$deferredResult instanceof DeferredResult) {
                $this->rateLimiter->record(0, 0);

                continue;
            }

            $this->cancelAndBook($deferredResult, $estimatedInputTokens);
        }
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    private function cancelAndBook(DeferredResult $deferredResult, int $estimatedInputTokens): void
    {
        $this->cancel($deferredResult);
        $this->rateLimiter->record($estimatedInputTokens, 0);
        $this->budgetTracker?->recordCall(LLMResponse::of('', $this->model, 'cancelled', TokenUsageSnapshot::of($estimatedInputTokens, 0, 0, 0)));
        $this->tokenUsageRecorder?->record($estimatedInputTokens, 0);
        $this->logger->debug('Cancelled a request still in flight; its estimated input tokens are booked as spent since the provider bills a request it accepted', [
            'estimated_input_tokens' => $estimatedInputTokens,
        ]);
    }

    private function cancel(?DeferredResult $deferredResult): void
    {
        $object = $deferredResult?->getRawResult()->getObject();
        if ($object instanceof ResponseInterface) {
            $object->cancel();
        }
    }
}
