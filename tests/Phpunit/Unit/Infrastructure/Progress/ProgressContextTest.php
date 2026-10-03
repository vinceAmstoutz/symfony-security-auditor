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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Progress;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressContext;

final class ProgressContextTest extends TestCase
{
    #[DataProvider('durationCases')]
    public function test_duration_suffix_formats_whole_seconds_and_omits_sub_second(mixed $value, string $expected): void
    {
        self::assertSame($expected, ProgressContext::durationSuffix(['elapsed_seconds' => $value], 'elapsed_seconds'));
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function durationCases(): iterable
    {
        yield 'whole seconds' => [47.0, ' (47s)'];
        yield 'rounds up at the half second' => [46.6, ' (47s)'];
        yield 'rounds down below the half second' => [46.4, ' (46s)'];
        yield 'exactly one second' => [1.0, ' (1s)'];
        yield 'sub-second is omitted' => [0.4, ''];
        yield 'zero is omitted' => [0.0, ''];
        yield 'non-float is omitted' => ['nope', ''];
    }

    public function test_duration_suffix_is_empty_when_the_key_is_absent(): void
    {
        self::assertSame('', ProgressContext::durationSuffix([], 'elapsed_seconds'));
    }

    /** @param array<string, mixed> $context */
    #[DataProvider('reviewOutcomes')]
    public function test_it_tells_a_review_that_reached_no_verdict_from_a_verdict(array $context, bool $expected): void
    {
        self::assertSame($expected, ProgressContext::reviewReachedNoVerdict($context));
    }

    /** @return iterable<string, array{array<string, mixed>, bool}> */
    public static function reviewOutcomes(): iterable
    {
        yield 'a review whose call failed' => [['accepted' => false, 'status' => 'errored'], true];
        yield 'a review an abort cut short' => [['accepted' => false, 'status' => 'aborted'], true];
        yield 'a rejection' => [['accepted' => false, 'status' => 'rejected'], false];
        yield 'a validation' => [['accepted' => true, 'status' => 'validated'], false];
        yield 'an event that names no status' => [['accepted' => false], false];
    }

    /** @param array<string, mixed> $context */
    #[DataProvider('reviewTallies')]
    public function test_the_review_tally_names_the_reviews_that_failed_only_when_some_did(array $context, string $expected): void
    {
        self::assertSame($expected, ProgressContext::reviewTally($context));
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function reviewTallies(): iterable
    {
        yield 'every review reached a verdict' => [['accepted' => 2, 'rejected' => 1, 'failed' => 0], '2 validated, 1 rejected'];
        yield 'an event that counts no failure' => [['accepted' => 2, 'rejected' => 1], '2 validated, 1 rejected'];
        yield 'some reviews failed' => [['accepted' => 1, 'rejected' => 1, 'failed' => 2], '1 validated, 1 rejected, 2 failed'];
    }
}
