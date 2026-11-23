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
 * Cancels the concurrent requests a sibling's failure left unread, so their
 * HTTP responses neither wait for the provider in their destructors nor
 * replace that failure. Books each at its estimated input tokens and no
 * output, since the provider bills a request it accepted.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
     * Cancels the failed request without booking it, since its spend is
     * already booked. A request whose dispatch failed only releases its
     * rate-limit reservation.
     *
     * @param array<int, array{?DeferredResult, int}> $unconsumed each request the window has not consumed, by window index: its deferred result (null when its dispatch failed) and its estimated input tokens
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
