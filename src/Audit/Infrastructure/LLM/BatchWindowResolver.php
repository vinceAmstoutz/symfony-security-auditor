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
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;

/**
 * Dispatches every request in a concurrency window via the platform WITHOUT
 * blocking, then resolves them. When the platform's transport is async (the
 * symfony/ai DeferredResult contract), the resolutions overlap on the wire.
 * Any request that fails to dispatch or resolve falls back to the proven
 * sequential complete() path (full retry) so the batch path is never less
 * correct than the per-call path — except for the failures a retry cannot
 * change: an answer with nothing usable in it comes back as the matching
 * degraded response, and a request the model or the rate-limit window cannot
 * take in is answered `request_too_large`, so the caller can act on that one
 * request while its siblings keep their answers. A failure that ends the
 * window cancels the requests still in flight and books their spend.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BatchWindowResolver
{
    public function __construct(
        private ?PlatformInterface $platform,
        private string $model,
        private RateLimiterInterface $rateLimiter,
        private ?BudgetTracker $budgetTracker,
        private PlatformResultExtractor $platformResultExtractor,
        private PlatformOptionsFactory $platformOptionsFactory,
        private PromptTokenEstimator $promptTokenEstimator,
        private LLMClientInterface $llmClient,
        private LoggerInterface $logger,
        private TransientFailureClassifier $transientFailureClassifier,
        private InFlightRequestCanceller $inFlightRequestCanceller,
        private DegradedAnswerBooker $degradedAnswerBooker,
        private ConversionFailureExplainer $conversionFailureExplainer,
    ) {}

    /**
     * @param list<LLMRequest> $window
     *
     * @return list<LLMResponse>
     *
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    public function resolveWindow(array $window): array
    {
        $platform = $this->platform ?? throw MissingAiPlatformException::create();
        $this->budgetTracker?->assertWithinBudget();

        return $this->resolveDispatched($window, $this->dispatch($platform, $window));
    }

    /**
     * A request larger than the whole rate-limit window is answered on the
     * spot instead of taking the window down with it.
     *
     * @param list<LLMRequest> $window
     *
     * @return array<int, DispatchedRequest>
     *
     * @throws InvalidTokenUsageException
     */
    private function dispatch(PlatformInterface $platform, array $window): array
    {
        $dispatched = [];
        foreach ($window as $index => $llmRequest) {
            $estimatedInputTokens = $this->promptTokenEstimator->estimate($llmRequest->system, $llmRequest->user);

            try {
                $this->rateLimiter->acquire($estimatedInputTokens);
            } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
                $dispatched[$index] = new DispatchedRequest(null, $estimatedInputTokens, $this->tooLargeResponse($llmRequestTooLargeException));

                continue;
            }

            $dispatched[$index] = new DispatchedRequest($this->invokeWithoutThrowing($platform, $llmRequest), $estimatedInputTokens);
        }

        return $dispatched;
    }

    private function invokeWithoutThrowing(PlatformInterface $platform, LLMRequest $llmRequest): ?DeferredResult
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        $messageBag = new MessageBag(
            Message::forSystem($llmRequest->system),
            Message::ofUser($llmRequest->user),
        );

        try {
            return $platform->invoke($this->model, $messageBag, $this->platformOptionsFactory->baseOptions());
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Every request of the window was already dispatched — and billed by the
     * provider — so every response is resolved and its spend recorded before
     * the budget verdict is given: a window that blows the budget then aborts
     * with the whole window's spend on the books rather than the first
     * response's alone. Any other failure ends the window, and the requests it
     * leaves in flight are cancelled and booked.
     *
     * @param list<LLMRequest>              $window
     * @param array<int, DispatchedRequest> $dispatched
     *
     * @return list<LLMResponse>
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    private function resolveDispatched(array $window, array $dispatched): array
    {
        $resolved = [];
        $unconsumed = $dispatched;
        foreach ($window as $index => $llmRequest) {
            try {
                $resolved[$index] = $this->resolveOne($dispatched[$index], $llmRequest);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->logger->debug('Budget exceeded while resolving a batch window; the remaining dispatched requests are still resolved so their spend is recorded', [
                    'error' => $budgetExceededException->getMessage(),
                ]);
            } catch (Throwable $throwable) {
                $this->cancelUnconsumed($unconsumed, $index);

                throw $throwable;
            }

            unset($unconsumed[$index]);
        }

        $this->budgetTracker?->assertWithinBudget();

        return array_values($resolved);
    }

    /**
     * The request whose resolution failed is cancelled but not booked: its
     * fallback call already recorded what it spent. A request answered before
     * dispatch took no rate-limit reservation, so there is nothing to release.
     *
     * @param array<int, DispatchedRequest> $unconsumed
     *
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    private function cancelUnconsumed(array $unconsumed, int $consumedFailedIndex): void
    {
        $open = [];
        foreach ($unconsumed as $index => $dispatchedRequest) {
            if (!$dispatchedRequest->answer instanceof LLMResponse) {
                $open[$index] = [$dispatchedRequest->deferredResult, $dispatchedRequest->estimatedInputTokens];
            }
        }

        $this->inFlightRequestCanceller->cancelAll($open, $consumedFailedIndex);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    private function resolveOne(DispatchedRequest $dispatchedRequest, LLMRequest $llmRequest): LLMResponse
    {
        if ($dispatchedRequest->answer instanceof LLMResponse) {
            return $dispatchedRequest->answer;
        }

        $deferredResult = $dispatchedRequest->deferredResult;
        if (!$deferredResult instanceof DeferredResult) {
            $this->rateLimiter->record(0, 0);

            return $this->completeOrRefuse($llmRequest);
        }

        $reconciled = false;

        try {
            $content = $deferredResult->asText();
            [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens] = $this->platformResultExtractor->extractTokens($deferredResult);
            $this->rateLimiter->record($inputTokens, $outputTokens);
            $reconciled = true;

            $llmResponse = LLMResponse::of(
                $content,
                $this->model,
                $this->platformResultExtractor->extractStopReason($deferredResult) ?? 'end_turn',
                TokenUsageSnapshot::of($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens),
            )->withReportedModel($this->platformResultExtractor->extractReportedModel($deferredResult));
            $this->budgetTracker?->recordCall($llmResponse);

            return $llmResponse;
        } catch (Throwable $throwable) {
            $failure = $this->conversionFailureExplainer->explain($throwable, $deferredResult);
            if (!$reconciled) {
                $this->rateLimiter->record($this->transientFailureClassifier->inputTokensTakenIn($failure, $dispatchedRequest->estimatedInputTokens), 0);
            }

            return $this->recoverFailedResolution($failure, $llmRequest, $dispatchedRequest->estimatedInputTokens);
        }
    }

    /**
     * A retry cannot change an answer with nothing usable in it, or a request
     * the model cannot take in, so those are answered as they are; any other
     * failure falls back to a fresh complete() call.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    private function recoverFailedResolution(Throwable $throwable, LLMRequest $llmRequest, int $estimatedInputTokens): LLMResponse
    {
        $degradedStopReason = $this->transientFailureClassifier->degradedStopReason($throwable);
        if (null !== $degradedStopReason) {
            $this->degradedAnswerBooker->book($estimatedInputTokens, $degradedStopReason);

            return LLMResponse::of('', $this->model, $degradedStopReason, TokenUsageSnapshot::of(0, 0));
        }

        if ($this->transientFailureClassifier->isRequestTooLarge($throwable)) {
            return $this->tooLargeResponse($throwable);
        }

        $this->logger->warning('Batch-window response failed to resolve after dispatch; falling back to a fresh complete() call that may duplicate provider billing for the already-dispatched request');

        return $this->completeOrRefuse($llmRequest);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    private function completeOrRefuse(LLMRequest $llmRequest): LLMResponse
    {
        try {
            return $this->llmClient->complete($llmRequest->system, $llmRequest->user);
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->tooLargeResponse($llmRequestTooLargeException);
        }
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function tooLargeResponse(Throwable $throwable): LLMResponse
    {
        $this->logger->debug('Batch request refused as too large for the model; it is answered as request_too_large so the caller can act on that request alone', [
            'error' => $throwable->getMessage(),
        ]);

        return LLMResponse::of($throwable->getMessage(), $this->model, 'request_too_large', TokenUsageSnapshot::of(0, 0));
    }
}
