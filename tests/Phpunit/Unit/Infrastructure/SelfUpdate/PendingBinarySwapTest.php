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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PendingBinarySwap;

final class PendingBinarySwapTest extends TestCase
{
    public function test_it_does_not_run_a_scheduled_swap_before_the_commit(): void
    {
        $ran = false;
        $pendingBinarySwap = new PendingBinarySwap();

        $pendingBinarySwap->schedule(static function () use (&$ran): void {
            $ran = true;
        });

        self::assertFalse($ran);
    }

    public function test_it_runs_a_scheduled_swap_on_commit(): void
    {
        $ran = false;
        $pendingBinarySwap = new PendingBinarySwap();
        $pendingBinarySwap->schedule(static function () use (&$ran): void {
            $ran = true;
        });

        $pendingBinarySwap->commit();

        self::assertTrue($ran);
    }

    public function test_it_runs_scheduled_swaps_in_the_order_they_were_scheduled(): void
    {
        $order = [];
        $pendingBinarySwap = new PendingBinarySwap();
        $pendingBinarySwap->schedule(static function () use (&$order): void {
            $order[] = 'first';
        });
        $pendingBinarySwap->schedule(static function () use (&$order): void {
            $order[] = 'second';
        });

        $pendingBinarySwap->commit();

        self::assertSame(['first', 'second'], $order);
    }

    public function test_it_runs_a_scheduled_swap_only_once_across_repeated_commits(): void
    {
        $runs = 0;
        $pendingBinarySwap = new PendingBinarySwap();
        $pendingBinarySwap->schedule(static function () use (&$runs): void {
            ++$runs;
        });

        $pendingBinarySwap->commit();
        $pendingBinarySwap->commit();

        self::assertSame(1, $runs);
    }
}
