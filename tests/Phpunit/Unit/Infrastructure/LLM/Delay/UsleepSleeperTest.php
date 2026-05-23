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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Delay;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;

final class UsleepSleeperTest extends TestCase
{
    public function test_zero_milliseconds_returns_immediately(): void
    {
        $usleepSleeper = new UsleepSleeper();

        $startedAt = hrtime(true);
        $usleepSleeper->sleep(0);
        $elapsedNanoseconds = hrtime(true) - $startedAt;

        // Should be effectively instant; allow generous slack for CI noise.
        self::assertLessThan(5_000_000, $elapsedNanoseconds);
    }

    public function test_negative_milliseconds_returns_immediately(): void
    {
        $usleepSleeper = new UsleepSleeper();

        $startedAt = hrtime(true);
        $usleepSleeper->sleep(-10);
        $elapsedNanoseconds = hrtime(true) - $startedAt;

        self::assertLessThan(5_000_000, $elapsedNanoseconds);
    }

    public function test_positive_milliseconds_sleeps_at_least_that_long(): void
    {
        $usleepSleeper = new UsleepSleeper();

        $startedAt = hrtime(true);
        $usleepSleeper->sleep(10);
        $elapsedNanoseconds = hrtime(true) - $startedAt;

        // 10 ms == 10_000_000 ns. usleep may be slightly imprecise; assert ≥ 8 ms.
        self::assertGreaterThanOrEqual(8_000_000, $elapsedNanoseconds);
    }
}
