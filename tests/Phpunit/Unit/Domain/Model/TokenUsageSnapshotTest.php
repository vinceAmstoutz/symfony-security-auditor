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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;

final class TokenUsageSnapshotTest extends TestCase
{
    public function test_of_creates_snapshot_with_given_counts(): void
    {
        $tokenUsageSnapshot = TokenUsageSnapshot::of(100, 50);

        self::assertSame(100, $tokenUsageSnapshot->inputTokens());
        self::assertSame(50, $tokenUsageSnapshot->outputTokens());
    }

    public function test_total_tokens_is_sum_of_input_and_output(): void
    {
        $tokenUsageSnapshot = TokenUsageSnapshot::of(120, 30);

        self::assertSame(150, $tokenUsageSnapshot->totalTokens());
    }

    public function test_zero_factory_creates_empty_snapshot(): void
    {
        $tokenUsageSnapshot = TokenUsageSnapshot::zero();

        self::assertSame(0, $tokenUsageSnapshot->inputTokens());
        self::assertSame(0, $tokenUsageSnapshot->outputTokens());
        self::assertSame(0, $tokenUsageSnapshot->totalTokens());
    }

    public function test_negative_input_tokens_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Input tokens must be >= 0, got -1');

        TokenUsageSnapshot::of(-1, 0);
    }

    public function test_negative_output_tokens_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Output tokens must be >= 0, got -3');

        TokenUsageSnapshot::of(0, -3);
    }
}
