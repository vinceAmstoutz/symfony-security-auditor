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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkFailureReason;

final class ChunkFailureReasonTest extends TestCase
{
    #[DataProvider('stopReasonCases')]
    public function test_a_stop_reason_is_named_in_words_a_person_can_act_on(string $stopReason, string $expected): void
    {
        self::assertSame($expected, ChunkFailureReason::fromStopReason($stopReason));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function stopReasonCases(): iterable
    {
        yield 'tool-call cap' => ['max_tool_iterations', 'tool-call limit reached (audit.max_tool_iterations)'];
        yield 'output token limit' => ['length', 'output token limit reached (max_output_tokens)'];
        yield 'content filter' => ['content-filter', 'answer withheld by the provider content filter'];
        yield 'empty answer' => ['empty_content', 'the model returned no content'];
        yield 'unknown stop reason' => ['something_new', 'answer cut short (something_new)'];
    }

    public function test_a_failure_is_named_by_its_message_on_one_line(): void
    {
        self::assertSame('Idle timeout reached for "https://api.example.com"', ChunkFailureReason::fromThrowable(new RuntimeException("Idle timeout reached\n   for \"https://api.example.com\"")));
    }

    public function test_a_long_failure_message_is_cut_so_the_progress_line_stays_short(): void
    {
        $reason = ChunkFailureReason::fromThrowable(new RuntimeException(str_repeat('a', 500)));

        self::assertSame(\sprintf('%s…', str_repeat('a', 119)), $reason);
    }

    public function test_a_failure_message_that_is_not_valid_utf8_is_still_named_instead_of_aborting_the_audit(): void
    {
        self::assertSame('Connection lost: bad ? byte', ChunkFailureReason::fromThrowable(new RuntimeException("Connection lost: bad \xFF byte")));
    }

    public function test_a_failure_without_a_message_is_named_by_its_class(): void
    {
        self::assertSame(RuntimeException::class, ChunkFailureReason::fromThrowable(new RuntimeException('')));
    }
}
