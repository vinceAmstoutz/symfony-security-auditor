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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ReleaseTag;

final class ReleaseTagTest extends TestCase
{
    #[DataProvider('releaseTags')]
    public function test_it_accepts_a_release_version_with_an_optional_prefix_and_pre_release(string $tag): void
    {
        self::assertTrue(ReleaseTag::isValid($tag));
    }

    /** @return iterable<string, array{string}> */
    public static function releaseTags(): iterable
    {
        yield 'a plain version' => ['1.21.0'];
        yield 'a multi-digit version' => ['10.200.3000'];
        yield 'a lowercase prefix' => ['v1.21.0'];
        yield 'an uppercase prefix' => ['V1.21.0'];
        yield 'a pre-release' => ['1.21.0-rc1'];
        yield 'a dotted pre-release' => ['1.21.0-rc.1'];
        yield 'a pre-release with several identifiers' => ['1.21.0-rc.1.2'];
        yield 'a hyphenated pre-release' => ['1.21.0-beta-2.x'];
        yield 'a prefixed pre-release' => ['v1.21.0-alpha'];
    }

    #[DataProvider('refusedTags')]
    public function test_it_refuses_anything_else(string $tag): void
    {
        self::assertFalse(ReleaseTag::isValid($tag));
    }

    /** @return iterable<string, array{string}> */
    public static function refusedTags(): iterable
    {
        yield 'an empty tag' => [''];
        yield 'a word' => ['latest'];
        yield 'a bare prefix' => ['v'];
        yield 'a double prefix' => ['vv1.21.0'];
        yield 'two components' => ['1.21'];
        yield 'four components' => ['1.21.0.1'];
        yield 'a non-numeric component' => ['1.x.0'];
        yield 'a leading space' => [' 1.21.0'];
        yield 'a trailing space' => ['1.21.0 '];
        yield 'trailing text' => ['1.21.0 latest'];
        yield 'leading text' => ['release-1.21.0'];
        yield 'a trailing newline' => ["1.21.0\n"];
        yield 'a leading newline' => ["\n1.21.0"];
        yield 'a null byte' => ["1.21.0\0"];
        yield 'a terminal escape' => ["1.21.0\x1b[31m"];
        yield 'a path traversal' => ['../../x'];
        yield 'a version followed by a path' => ['1.21.0/../../x'];
        yield 'a version followed by a query' => ['1.21.0?x=1'];
        yield 'a version followed by a fragment' => ['1.21.0#x'];
        yield 'a url' => ['https://evil.test/1.21.0'];
        yield 'an empty pre-release' => ['1.21.0-'];
        yield 'an empty pre-release identifier' => ['1.21.0-rc..1'];
        yield 'a trailing pre-release dot' => ['1.21.0-rc.'];
        yield 'a leading pre-release dot' => ['1.21.0-.rc'];
        yield 'a pre-release with a slash' => ['1.21.0-rc/1'];
        yield 'build metadata' => ['1.21.0+build'];
        yield 'an underscore pre-release' => ['1.21.0-rc_1'];
        yield 'a non-ascii digit' => ['١.٢.٣'];
    }
}
