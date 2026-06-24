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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit;

use DateTimeImmutable;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RateLimitRequestTooLargeException;

/**
 * Fixed-minute token bucket with three independent dimensions (RPM, ITPM, OTPM).
 *
 * `acquire()` blocks until the next request fits inside the current window —
 * either because capacity is available or because the next reset is reached.
 * `record()` reconciles the pre-call input estimate with the post-call actual
 * so subsequent `acquire()` decisions stay accurate. `pauseUntil()` propagates
 * a server-issued `Retry-After` into the bucket so chunks scheduled after the
 * 429 cooperatively wait instead of stampeding the provider.
 *
 * Class invariant: at least one rate-limit dimension is set. The bundle wires
 * `NullRateLimiter` when all dimensions are null, so this class is never
 * instantiated with a fully-disabled configuration — enforced in the
 * constructor.
 *
 * State is per-process: multiple processes sharing one API key still need
 * out-of-process coordination (Redis/file lock) — out of scope here.
 *
 * Not `readonly` because the bucket carries mutable accounting state; see
 * `.claude/rules/php-classes.md` (stateful collaborator carve-out — same
 * shape as `BudgetTracker`).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class TokenBucketRateLimiter implements RateLimiterInterface
{
    private const int WINDOW_DURATION_SECONDS = 60;

    private DateTimeImmutable $windowStart;

    private int $requestsUsed = 0;

    private int $inputTokensUsed = 0;

    private int $outputTokensUsed = 0;

    private int $pendingInputEstimate = 0;

    private ?DateTimeImmutable $pausedUntil = null;

    public function __construct(
        private readonly RateLimitConfiguration $rateLimitConfiguration,
        private readonly ClockInterface $clock,
        private readonly SleeperInterface $sleeper,
    ) {
        if (!$rateLimitConfiguration->isEnabled()) {
            throw new InvalidArgumentException('TokenBucketRateLimiter requires at least one rate-limit dimension; wire NullRateLimiter for fully-disabled config.');
        }

        $this->windowStart = $this->floorToMinute($this->clock->now());
    }

    public function acquire(int $estimatedInputTokens): void
    {
        $this->assertAcceptableEstimate($estimatedInputTokens);

        while (true) {
            $now = $this->currentInstant();

            if ($this->sleptThroughActivePause($now)) {
                continue;
            }

            $this->resetWindowIfExpired($now);

            if ($this->tryReserve($estimatedInputTokens)) {
                return;
            }

            $this->sleepUntil($now, $this->nextWindowStart());
        }
    }

    private function assertAcceptableEstimate(int $estimatedInputTokens): void
    {
        if ($estimatedInputTokens < 0) {
            throw new InvalidArgumentException(\sprintf('estimatedInputTokens must be >= 0, got %d', $estimatedInputTokens));
        }

        $itpm = $this->rateLimitConfiguration->inputTokensPerMinute;
        if (null !== $itpm && $estimatedInputTokens > $itpm) {
            throw RateLimitRequestTooLargeException::from($estimatedInputTokens, $itpm);
        }
    }

    private function sleptThroughActivePause(DateTimeImmutable $now): bool
    {
        $pausedUntil = $this->pausedUntil;
        if (!$pausedUntil instanceof DateTimeImmutable || $now >= $pausedUntil) {
            return false;
        }

        $this->sleepUntil($now, $pausedUntil);

        return true;
    }

    private function tryReserve(int $estimatedInputTokens): bool
    {
        if (!$this->capacityAvailable($estimatedInputTokens)) {
            return false;
        }

        ++$this->requestsUsed;
        $this->inputTokensUsed += $estimatedInputTokens;
        $this->pendingInputEstimate = $estimatedInputTokens;

        return true;
    }

    public function record(int $inputTokens, int $outputTokens): void
    {
        $this->inputTokensUsed = $this->inputTokensUsed - $this->pendingInputEstimate + $inputTokens;
        $this->pendingInputEstimate = 0;
        $this->outputTokensUsed += $outputTokens;
    }

    public function pauseUntil(DateTimeImmutable $until): void
    {
        $this->pausedUntil = $until;
    }

    private function currentInstant(): DateTimeImmutable
    {
        return DateTimeImmutable::createFromInterface($this->clock->now());
    }

    private function capacityAvailable(int $estimatedInputTokens): bool
    {
        $rpm = $this->rateLimitConfiguration->requestsPerMinute;
        if (null !== $rpm && $this->requestsUsed >= $rpm) {
            return false;
        }

        $itpm = $this->rateLimitConfiguration->inputTokensPerMinute;
        if (null !== $itpm && ($this->inputTokensUsed + $estimatedInputTokens) > $itpm) {
            return false;
        }

        $otpm = $this->rateLimitConfiguration->outputTokensPerMinute;
        if (null !== $otpm && $this->outputTokensUsed >= $otpm) {
            return false;
        }

        return true;
    }

    private function resetWindowIfExpired(DateTimeImmutable $now): void
    {
        if ($now < $this->nextWindowStart()) {
            return;
        }

        $this->windowStart = $this->floorToMinute($now);
        $this->requestsUsed = 0;
        $this->inputTokensUsed = 0;
        $this->outputTokensUsed = 0;
    }

    private function nextWindowStart(): DateTimeImmutable
    {
        return $this->windowStart->modify(\sprintf('+%d seconds', self::WINDOW_DURATION_SECONDS));
    }

    private function floorToMinute(DateTimeImmutable $instant): DateTimeImmutable
    {
        $unix = (int) $instant->format('U');

        return $instant->setTimestamp($unix - ($unix % self::WINDOW_DURATION_SECONDS));
    }

    private function sleepUntil(DateTimeImmutable $from, DateTimeImmutable $to): void
    {
        $deltaUs = $to->format('Uu') - $from->format('Uu');
        $this->sleeper->sleep((int) ceil($deltaUs / 1_000));
    }
}
