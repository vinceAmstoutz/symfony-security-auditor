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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Telemetry;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;

final class TokenUsageRecorderTest extends TestCase
{
    public function test_fresh_recorder_snapshots_to_zero_zero(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(0, $snapshot->inputTokens());
        self::assertSame(0, $snapshot->outputTokens());
        self::assertSame(0, $snapshot->totalTokens());
    }

    public function test_single_record_call_is_reflected_in_snapshot(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $tokenUsageRecorder->record(120, 30);

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(120, $snapshot->inputTokens());
        self::assertSame(30, $snapshot->outputTokens());
        self::assertSame(150, $snapshot->totalTokens());
    }

    public function test_multiple_record_calls_accumulate(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $tokenUsageRecorder->record(50, 10);
        $tokenUsageRecorder->record(30, 5);
        $tokenUsageRecorder->record(70, 20);

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(150, $snapshot->inputTokens());
        self::assertSame(35, $snapshot->outputTokens());
    }

    public function test_reset_clears_accumulated_state(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(100, 50);

        $tokenUsageRecorder->reset();

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(0, $snapshot->inputTokens());
        self::assertSame(0, $snapshot->outputTokens());
    }

    public function test_recording_after_reset_starts_from_zero(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(100, 50);
        $tokenUsageRecorder->reset();

        $tokenUsageRecorder->record(7, 3);

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(7, $snapshot->inputTokens());
        self::assertSame(3, $snapshot->outputTokens());
    }

    public function test_cache_tokens_accumulate_across_record_calls(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $tokenUsageRecorder->record(10, 5, 40, 12);
        $tokenUsageRecorder->record(20, 10, 8, 3);

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(48, $snapshot->cacheReadTokens());
        self::assertSame(15, $snapshot->cacheCreationTokens());
    }

    public function test_cache_tokens_default_to_zero_when_omitted(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $tokenUsageRecorder->record(10, 5);

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(0, $snapshot->cacheReadTokens());
        self::assertSame(0, $snapshot->cacheCreationTokens());
    }

    public function test_reset_clears_accumulated_cache_tokens(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(10, 5, 40, 12);

        $tokenUsageRecorder->reset();

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(0, $snapshot->cacheReadTokens());
        self::assertSame(0, $snapshot->cacheCreationTokens());
    }

    public function test_recording_negative_cache_read_tokens_throws(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cache read tokens must be >= 0, got -2');

        $tokenUsageRecorder->record(0, 0, -2, 0);
    }

    public function test_recording_negative_cache_creation_tokens_throws(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cache creation tokens must be >= 0, got -7');

        $tokenUsageRecorder->record(0, 0, 0, -7);
    }

    public function test_recording_negative_input_tokens_throws(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Input tokens must be >= 0, got -1');

        $tokenUsageRecorder->record(-1, 0);
    }

    public function test_recording_negative_output_tokens_throws(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Output tokens must be >= 0, got -5');

        $tokenUsageRecorder->record(0, -5);
    }

    public function test_snapshot_does_not_observe_subsequent_recording(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(10, 5);

        $tokenUsageSnapshot = $tokenUsageRecorder->snapshot();
        $tokenUsageRecorder->record(20, 10);

        self::assertSame(10, $tokenUsageSnapshot->inputTokens());
        self::assertSame(5, $tokenUsageSnapshot->outputTokens());
    }

    public function test_later_snapshot_observes_cumulative_state(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(10, 5);
        $tokenUsageRecorder->record(20, 10);

        $tokenUsageSnapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(30, $tokenUsageSnapshot->inputTokens());
        self::assertSame(15, $tokenUsageSnapshot->outputTokens());
    }

    public function test_recording_zero_tokens_does_not_change_state(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(100, 50);

        $tokenUsageRecorder->record(0, 0);

        $snapshot = $tokenUsageRecorder->snapshot();

        self::assertSame(100, $snapshot->inputTokens());
        self::assertSame(50, $snapshot->outputTokens());
    }
}
