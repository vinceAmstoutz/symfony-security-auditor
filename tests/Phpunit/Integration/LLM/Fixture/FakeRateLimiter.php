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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use DateTimeImmutable;
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;

final class FakeRateLimiter implements RateLimiterInterface
{
    /** @var list<int> */
    public array $acquired = [];

    /** @var list<array{int, int}> */
    public array $recorded = [];

    /** @var list<DateTimeImmutable> */
    public array $paused = [];

    #[Override]
    public function acquire(int $estimatedInputTokens): void
    {
        $this->acquired[] = $estimatedInputTokens;
    }

    #[Override]
    public function record(int $inputTokens, int $outputTokens): void
    {
        $this->recorded[] = [$inputTokens, $outputTokens];
    }

    #[Override]
    public function pauseUntil(DateTimeImmutable $until): void
    {
        $this->paused[] = $until;
    }
}
