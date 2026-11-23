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

use DateTimeImmutable;
use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Result\DeferredResult;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\ProviderMessageRedactor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\SuggestedWaitParser;

/**
 * Invokes the platform behind the rate limiter, retrying transient failures
 * and throwing the matching exception for any other. A rate limit waits at
 * least the server's Retry-After. Books every failed attempt and sends no
 * retry past the budget; the caller checks the budget before the first
 * attempt.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class RetryingPlatformInvoker
{
    public function __construct(
        private PlatformBinding $platformBinding,
        private string $model,
        private LoggerInterface $logger,
        private RateLimiterInterface $rateLimiter,
        private RetryPolicy $retryPolicy,
        private TransientFailureClassifier $transientFailureClassifier,
        private SleeperInterface $sleeper,
        private RetryAfterHeaderParser $retryAfterHeaderParser,
        private ConversionFailureExplainer $conversionFailureExplainer,
        private DegradedAnswerBooker $degradedAnswerBooker,
        private ?BudgetTracker $budgetTracker,
        private SuggestedWaitParser $suggestedWaitParser = new SuggestedWaitParser(),
        private OutputCapRaise $outputCapRaise = new OutputCapRaise(),
    ) {}

    /**
     * @param array<string, mixed> $options
     *
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws EmptyLLMResponseException
     * @throws LLMRequestTooLargeException
     * @throws NonTransientLLMFailureException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws BudgetExceededException
     */
    public function invoke(MessageBag $messageBag, array $options, int $estimatedInputTokens): DeferredResult
    {
        $platform = $this->platformBinding->platform();

        \assert('' !== $this->model, 'Model must be a non-empty string');

        $maxAttempts = $this->retryPolicy->maxAttempts();
        $attempt = 1;
        $capRaisable = true;
        while (true) {
            $this->rateLimiter->acquire($estimatedInputTokens);
            $deferredResult = null;

            try {
                $deferredResult = $platform->invoke($this->model, $messageBag, $options);
                $deferredResult->getResult();

                return $deferredResult;
            } catch (Throwable $throwable) {
                $failure = $this->explainedFailure($throwable, $deferredResult, $attempt >= $maxAttempts);
                $this->degradedAnswerBooker->bookFailedCall($failure, $deferredResult, $estimatedInputTokens);
                $raisedOptions = $this->optionsWithARaisedCap($failure, $options, $capRaisable);
                if (null !== $raisedOptions) {
                    $options = $raisedOptions;
                    $capRaisable = false;

                    continue;
                }

                $this->rethrowWhenNonTransient($failure);
                $this->prepareRetry($failure, $deferredResult, $attempt, $maxAttempts);
                ++$attempt;
            }
        }
    }

    /**
     * @throws TransientLLMFailureException
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     */
    private function prepareRetry(Throwable $failure, ?DeferredResult $deferredResult, int $attempt, int $maxAttempts): void
    {
        if ($attempt >= $maxAttempts) {
            throw TransientLLMFailureException::afterExhaustedAttempts($maxAttempts, $failure);
        }

        $this->budgetTracker?->assertWithinBudget();
        $this->backOffBeforeNextAttempt($failure, $deferredResult, $attempt, $maxAttempts);
    }

    /**
     * Returns the options that ask again, once, with a higher cap for a tool
     * call the output cap cut off.
     *
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>|null
     *
     * @throws BudgetExceededException
     */
    private function optionsWithARaisedCap(Throwable $throwable, array $options, bool $capRaisable): ?array
    {
        if (!$capRaisable || !$this->transientFailureClassifier->isToolCallCutByTheOutputCap($throwable)) {
            return null;
        }

        $raisedOptions = $this->outputCapRaise->raised($options);
        if (null !== $raisedOptions) {
            $this->budgetTracker?->assertWithinBudget();
            $this->logger->warning('LLM tool call cut off by the output token cap, asking again with a higher cap', [
                'error' => ProviderMessageRedactor::redact($throwable->getMessage()),
            ]);
        }

        return $raisedOptions;
    }

    /**
     * Reads a status that clears on its own as the failure without that status
     * once the retries are spent.
     */
    private function explainedFailure(Throwable $throwable, ?DeferredResult $deferredResult, bool $retriesSpent): Throwable
    {
        $failure = $this->conversionFailureExplainer->explain($throwable, $deferredResult);

        return $retriesSpent && $failure instanceof TransientHttpStatusException ? $failure->statusFreeFailure : $failure;
    }

    /**
     * @throws EmptyLLMResponseException
     * @throws LLMRequestTooLargeException
     * @throws NonTransientLLMFailureException
     */
    private function rethrowWhenNonTransient(Throwable $throwable): void
    {
        $degradedStopReason = $this->transientFailureClassifier->degradedStopReason($throwable);
        if (null !== $degradedStopReason) {
            throw EmptyLLMResponseException::from($throwable, $degradedStopReason);
        }

        if ($this->transientFailureClassifier->isRequestTooLarge($throwable)) {
            throw LLMRequestTooLargeException::fromProviderRejection($throwable);
        }

        if (!$this->transientFailureClassifier->isTransient($throwable)) {
            throw NonTransientLLMFailureException::from($throwable);
        }
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    private function backOffBeforeNextAttempt(Throwable $throwable, ?DeferredResult $deferredResult, int $attempt, int $maxAttempts): void
    {
        $isRateLimit = $this->transientFailureClassifier->isRateLimit($throwable);
        $serverHintSeconds = $isRateLimit ? $this->retryAfterHeaderParser->parse($throwable) : null;

        $delay = $isRateLimit
            ? $this->retryPolicy->rateLimitDelayAtLeastMs($attempt, $serverHintSeconds, $this->suggestedWaitParser->milliseconds($throwable, $deferredResult))
            : $this->retryPolicy->delayMs($attempt);

        if (null !== $serverHintSeconds) {
            $this->rateLimiter->pauseUntil(
                (new DateTimeImmutable())->modify(\sprintf('+%d milliseconds', $delay)),
            );
        }

        $this->logger->warning('LLM call failed, retrying after backoff', [
            'attempt' => $attempt,
            'max_attempts' => $maxAttempts,
            'delay_ms' => $delay,
            'error' => ProviderMessageRedactor::redact($throwable->getMessage()),
        ]);
        $this->sleeper->sleep($delay);
    }
}
