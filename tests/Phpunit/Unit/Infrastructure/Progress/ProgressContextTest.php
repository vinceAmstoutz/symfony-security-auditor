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
}
