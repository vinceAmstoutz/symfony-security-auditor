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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay;

use Closure;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class UsleepSleeper implements SleeperInterface
{
    public const int MICROSECONDS_PER_MILLISECOND = 1000;

    /** @var Closure(int): void */
    private Closure $usleep;

    /** @param ?Closure(int): void $usleep test seam: defaults to PHP's usleep */
    public function __construct(?Closure $usleep = null)
    {
        $this->usleep = $usleep ?? usleep(...);
    }

    public function sleep(int $milliseconds): void
    {
        if ($milliseconds <= 0) {
            return;
        }

        ($this->usleep)($milliseconds * self::MICROSECONDS_PER_MILLISECOND);
    }
}
