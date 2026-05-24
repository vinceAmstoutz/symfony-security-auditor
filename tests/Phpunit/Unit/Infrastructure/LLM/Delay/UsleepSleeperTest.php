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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;

final class UsleepSleeperTest extends TestCase
{
    #[DataProvider('nonPositiveDurationCases')]
    public function test_non_positive_milliseconds_skip_the_usleep_call(int $milliseconds): void
    {
        $invocations = [];
        $usleepSleeper = new UsleepSleeper(static function (int $microseconds) use (&$invocations): void {
            $invocations[] = $microseconds;
        });

        $usleepSleeper->sleep($milliseconds);

        self::assertSame([], $invocations);
    }

    /** @return iterable<string, array{int}> */
    public static function nonPositiveDurationCases(): iterable
    {
        yield 'zero' => [0];
        yield 'negative_one' => [-1];
        yield 'large_negative' => [-1_000];
    }

    public function test_positive_milliseconds_invoke_usleep_with_milliseconds_times_one_thousand(): void
    {
        $invocations = [];
        $usleepSleeper = new UsleepSleeper(static function (int $microseconds) use (&$invocations): void {
            $invocations[] = $microseconds;
        });

        $usleepSleeper->sleep(10);

        self::assertSame([10_000], $invocations);
    }

    public function test_microseconds_per_millisecond_constant_is_exactly_one_thousand(): void
    {
        self::assertSame(1_000, UsleepSleeper::MICROSECONDS_PER_MILLISECOND);
    }

    public function test_default_constructor_uses_real_usleep_for_actual_blocking(): void
    {
        $usleepSleeper = new UsleepSleeper();

        $startedAt = hrtime(true);
        $usleepSleeper->sleep(10);
        $elapsedNanoseconds = hrtime(true) - $startedAt;

        self::assertGreaterThanOrEqual(8_000_000, $elapsedNanoseconds);
    }

    public function test_one_millisecond_boundary_value_triggers_usleep(): void
    {
        $invocations = [];
        $usleepSleeper = new UsleepSleeper(static function (int $microseconds) use (&$invocations): void {
            $invocations[] = $microseconds;
        });

        $usleepSleeper->sleep(1);

        self::assertSame([1_000], $invocations);
    }
}
