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
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;

/**
 * Invokes the platform behind the rate limiter with transient-failure retry:
 * empty-content and non-transient failures are classified into the matching
 * custom exception, rate-limit failures honor the server's Retry-After hint,
 * and other transient failures back off per the retry policy. Every failed
 * attempt is booked first, so one the provider answered and billed is on the
 * books whether it is retried or not, and no retry goes out once that spend
 * has run past the budget. The caller checks the budget before the first
 * attempt.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RetryingPlatformInvoker
{
    public function __construct(
        private ?PlatformInterface $platform,
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
        $platform = $this->platform ?? throw MissingAiPlatformException::create();

        \assert('' !== $this->model, 'Model must be a non-empty string');

        $maxAttempts = $this->retryPolicy->maxAttempts();
        $attempt = 1;
        while (true) {
            $this->rateLimiter->acquire($estimatedInputTokens);
            $deferredResult = null;

            try {
                $deferredResult = $platform->invoke($this->model, $messageBag, $options);
                $deferredResult->getResult();

                return $deferredResult;
            } catch (Throwable $throwable) {
                $failure = $this->conversionFailureExplainer->explain($throwable, $deferredResult);
                $this->degradedAnswerBooker->bookFailedCall($failure, $deferredResult, $estimatedInputTokens);
                $this->rethrowWhenNonTransient($failure);

                if ($attempt >= $maxAttempts) {
                    throw TransientLLMFailureException::afterExhaustedAttempts($maxAttempts, $failure);
                }

                $this->budgetTracker?->assertWithinBudget();
                $this->backOffBeforeNextAttempt($failure, $attempt, $maxAttempts);
                ++$attempt;
            }
        }
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
    private function backOffBeforeNextAttempt(Throwable $throwable, int $attempt, int $maxAttempts): void
    {
        $isRateLimit = $this->transientFailureClassifier->isRateLimit($throwable);
        $serverHintSeconds = $isRateLimit ? $this->retryAfterHeaderParser->parse($throwable) : null;

        $delay = $isRateLimit
            ? $this->retryPolicy->rateLimitDelayMs($attempt, $serverHintSeconds)
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
            'error' => $throwable->getMessage(),
        ]);
        $this->sleeper->sleep($delay);
    }
}
