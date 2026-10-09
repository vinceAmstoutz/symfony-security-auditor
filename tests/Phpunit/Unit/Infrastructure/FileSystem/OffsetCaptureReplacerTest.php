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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem;

use Override;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\OffsetCaptureReplacer;

final class OffsetCaptureReplacerTest extends TestCase
{
    private OffsetCaptureReplacer $offsetCaptureReplacer;

    public function test_it_replaces_each_match_and_keeps_the_text_around_and_between_them(): void
    {
        $output = $this->offsetCaptureReplacer->replace('/#(\d+)/', 'a #1 b #22 c', static fn (array $match): string => '<'.$match[1][0].'>');

        self::assertSame('a <1> b <22> c', $output);
    }

    public function test_it_hands_the_callback_the_text_and_the_offset_of_every_group(): void
    {
        $output = $this->offsetCaptureReplacer->replace('/(k)=(v+)?/', 'xx k=vv yy k=', static fn (array $match): string => json_encode($match, \JSON_THROW_ON_ERROR));

        self::assertSame('xx [["k=vv",3],["k",3],["vv",5]] yy [["k=",11],["k",11]]', $output);
    }

    public function test_it_returns_the_content_untouched_when_nothing_matches(): void
    {
        self::assertSame('abc', $this->offsetCaptureReplacer->replace('/#/', 'abc', static fn (array $match): string => 'x'));
    }

    public function test_it_returns_an_empty_string_for_empty_content(): void
    {
        self::assertSame('', $this->offsetCaptureReplacer->replace('/#/', '', static fn (array $match): string => 'x'));
    }

    public function test_it_replaces_a_match_that_starts_and_ends_the_content(): void
    {
        self::assertSame('<ab>', $this->offsetCaptureReplacer->replace('/ab/', 'ab', static fn (array $match): string => '<ab>'));
    }

    public function test_it_returns_null_when_the_engine_refuses_to_evaluate_the_pattern(): void
    {
        $previousLimit = \ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '50');

        try {
            $output = $this->offsetCaptureReplacer->replace('/^(a+)+$/', str_repeat('a', 30).'b', static fn (array $match): string => 'x');
        } finally {
            ini_set('pcre.backtrack_limit', false === $previousLimit ? '1000000' : $previousLimit);
        }

        self::assertNull($output);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->offsetCaptureReplacer = new OffsetCaptureReplacer();
    }
}
