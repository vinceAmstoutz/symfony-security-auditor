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
use Override;
use Psr\Clock\ClockInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RateLimitRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\Exception\InvalidRateLimiterConfigurationException;

/**
 * Fixed-minute token bucket over requests, input tokens and output tokens per
 * minute, with at least one limit set. acquire() blocks until the request
 * fits the window, record() replaces its input estimate with the usage and
 * pauseUntil() makes every later acquire() wait out a server's Retry-After.
 * Its state is per process.
 *
 * Not `readonly`: it keeps a rate window (`.claude/rules/php-classes.md`).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class TokenBucketRateLimiter implements RateLimiterInterface
{
    private const int WINDOW_DURATION_SECONDS = 60;

    private DateTimeImmutable $windowStart;

    private int $requestsUsed = 0;

    private int $inputTokensUsed = 0;

    private int $outputTokensUsed = 0;

    /** @var list<int> FIFO queue: one entry per unreconciled acquire(), oldest first */
    private array $pendingInputEstimates = [];

    private ?DateTimeImmutable $pausedUntil = null;

    /**
     * @throws InvalidRateLimiterConfigurationException
     */
    public function __construct(
        private readonly RateLimitConfiguration $rateLimitConfiguration,
        private readonly ClockInterface $clock,
        private readonly SleeperInterface $sleeper,
    ) {
        if (!$rateLimitConfiguration->isEnabled()) {
            throw InvalidRateLimiterConfigurationException::forNoEnabledDimension();
        }

        $this->windowStart = $this->floorToMinute($this->clock->now());
    }

    /**
     * @throws InvalidRateLimiterConfigurationException
     * @throws RateLimitRequestTooLargeException
     */
    #[Override]
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

    /**
     * @throws InvalidRateLimiterConfigurationException
     * @throws RateLimitRequestTooLargeException
     */
    private function assertAcceptableEstimate(int $estimatedInputTokens): void
    {
        if ($estimatedInputTokens < 0) {
            throw InvalidRateLimiterConfigurationException::forNegativeEstimatedInputTokens($estimatedInputTokens);
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
        $this->pendingInputEstimates[] = $estimatedInputTokens;

        return true;
    }

    #[Override]
    public function record(int $inputTokens, int $outputTokens): void
    {
        $pendingEstimate = array_shift($this->pendingInputEstimates) ?? 0;
        $this->inputTokensUsed = $this->inputTokensUsed - $pendingEstimate + $inputTokens;
        $this->outputTokensUsed += $outputTokens;
    }

    #[Override]
    public function pauseUntil(DateTimeImmutable $until): void
    {
        $this->pausedUntil = $this->pausedUntil instanceof DateTimeImmutable
            ? max($this->pausedUntil, $until)
            : $until;
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

    /**
     * Zeroes the pending estimates but keeps their slots, so a call that
     * straddles the reset neither subtracts a reservation the new window never
     * held nor shifts the reconciliation order.
     */
    private function resetWindowIfExpired(DateTimeImmutable $now): void
    {
        if ($now < $this->nextWindowStart()) {
            return;
        }

        $this->windowStart = $this->floorToMinute($now);
        $this->requestsUsed = 0;
        $this->inputTokensUsed = 0;
        $this->outputTokensUsed = 0;
        $this->pendingInputEstimates = array_map(static fn (): int => 0, $this->pendingInputEstimates);
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
