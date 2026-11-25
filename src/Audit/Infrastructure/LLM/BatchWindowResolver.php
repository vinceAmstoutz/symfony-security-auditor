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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\ProviderMessageRedactor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;

/**
 * Dispatches every request of a concurrency window before resolving any. A
 * request that fails to dispatch or resolve falls back to complete(). An
 * answer with nothing usable in it comes back as the matching degraded
 * response instead; a request the model or the rate-limit window cannot take
 * in is answered `request_too_large` while its siblings keep their answers. A
 * failure that ends the window cancels the requests in flight and books their
 * spend.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class BatchWindowResolver
{
    public function __construct(
        private PlatformBinding $platformBinding,
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
        $platform = $this->platformBinding->platform();
        $this->budgetTracker?->assertWithinBudget();

        return $this->resolveDispatched($window, $this->dispatch($platform, $window));
    }

    /**
     * Answers a request larger than the whole rate-limit window on the spot,
     * leaving the others running.
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
     * Checks the budget only once every billed response is resolved and
     * booked. Any other failure ends the window, cancelling and booking the
     * requests left in flight.
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
     * Cancels the failed request without booking it, since its fallback call
     * booked its spend. Skips a request answered before dispatch.
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
     * @throws TransientLLMFailureException
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
            $content = $this->platformResultExtractor->extractText($deferredResult->getResult());
            $tokenUsageSnapshot = TokenUsageSnapshot::of(...$this->platformResultExtractor->extractTokens($deferredResult, $dispatchedRequest->estimatedInputTokens));
            $this->rateLimiter->record($this->platformResultExtractor->rateLimitedInputTokens($deferredResult, $tokenUsageSnapshot), $tokenUsageSnapshot->outputTokens());
            $reconciled = true;

            $llmResponse = LLMResponse::of(
                $content,
                $this->model,
                $this->platformResultExtractor->extractStopReason($deferredResult),
                $tokenUsageSnapshot,
            )->withReportedModel($this->platformResultExtractor->extractReportedModel($deferredResult));
            $this->budgetTracker?->recordCall($llmResponse, $this->platformResultExtractor->extractOneHourCacheCreationTokens($deferredResult, $tokenUsageSnapshot->cacheCreationTokens()));

            return $llmResponse;
        } catch (Throwable $throwable) {
            $failure = $this->conversionFailureExplainer->explain($throwable, $deferredResult);
            if (!$reconciled) {
                $this->degradedAnswerBooker->bookFailedCall($failure, $deferredResult, $dispatchedRequest->estimatedInputTokens);
            }

            return $this->recoverFailedResolution($failure, $llmRequest);
        }
    }

    /**
     * Answers a degraded answer or a request the model cannot take in as it
     * is; any other failure falls back to complete().
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws TransientLLMFailureException
     */
    private function recoverFailedResolution(Throwable $throwable, LLMRequest $llmRequest): LLMResponse
    {
        $degradedStopReason = $this->transientFailureClassifier->degradedStopReason($throwable);
        if (null !== $degradedStopReason) {
            return LLMResponse::of('', $this->model, $degradedStopReason, TokenUsageSnapshot::of(0, 0));
        }

        if ($this->transientFailureClassifier->isRequestTooLarge($throwable)) {
            return $this->tooLargeResponse($throwable);
        }

        $this->logger->warning('Batch-window response failed to resolve after dispatch; falling back to a fresh complete() call that may duplicate provider billing for the already-dispatched request');

        return $this->completeOrRefuse($llmRequest);
    }

    /**
     * Replaces a request whose dispatch or resolution failed; a retry that
     * runs out counts that failed request as one more attempt.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws TransientLLMFailureException
     */
    private function completeOrRefuse(LLMRequest $llmRequest): LLMResponse
    {
        try {
            return $this->llmClient->complete($llmRequest->system, $llmRequest->user);
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->tooLargeResponse($llmRequestTooLargeException);
        } catch (TransientLLMFailureException $transientLLMFailureException) {
            throw $transientLLMFailureException->afterOneMoreAttempt();
        }
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function tooLargeResponse(Throwable $throwable): LLMResponse
    {
        $refusal = ProviderMessageRedactor::redact($throwable->getMessage());
        $this->logger->debug('Batch request refused as too large for the model; it is answered as request_too_large so the caller can act on that request alone', [
            'error' => $refusal,
        ]);

        return LLMResponse::of($refusal, $this->model, 'request_too_large', TokenUsageSnapshot::of(0, 0));
    }
}
