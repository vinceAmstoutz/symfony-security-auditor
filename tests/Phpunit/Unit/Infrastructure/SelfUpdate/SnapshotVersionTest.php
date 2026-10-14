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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SnapshotVersion;

final class SnapshotVersionTest extends TestCase
{
    #[DataProvider('snapshotVersions')]
    public function test_it_accepts_a_release_with_the_commits_since_and_the_commit_built(string $version): void
    {
        self::assertTrue(SnapshotVersion::isValid($version));
    }

    /** @return iterable<string, array{string}> */
    public static function snapshotVersions(): iterable
    {
        yield 'a short hash' => ['1.21.0+14.g4531440'];
        yield 'a full hash' => ['1.21.0+1.g4531440aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'];
        yield 'no commit since the release' => ['1.21.0+0.g4531440'];
        yield 'multi-digit components' => ['10.200.3000+1234.gabcdef0'];
    }

    #[DataProvider('refusedVersions')]
    public function test_it_refuses_anything_else(string $version): void
    {
        self::assertFalse(SnapshotVersion::isValid($version));
    }

    /** @return iterable<string, array{string}> */
    public static function refusedVersions(): iterable
    {
        yield 'an empty version' => [''];
        yield 'a release' => ['1.21.0'];
        yield 'a word' => ['snapshot'];
        yield 'the git describe form' => ['1.21.0-14-g4531440'];
        yield 'a prefixed version' => ['v1.21.0+14.g4531440'];
        yield 'a pre-release' => ['1.21.0-rc.1+14.g4531440'];
        yield 'two components' => ['1.21+14.g4531440'];
        yield 'no commit count' => ['1.21.0+g4531440'];
        yield 'no hash marker' => ['1.21.0+14.4531440'];
        yield 'a hash too short' => ['1.21.0+14.g453144'];
        yield 'a hash too long' => ['1.21.0+14.g4531440aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'];
        yield 'an uppercase hash' => ['1.21.0+14.g4531440ABC'];
        yield 'leading text' => ['x1.21.0+14.g4531440'];
        yield 'a trailing newline' => ["1.21.0+14.g4531440\n"];
        yield 'a terminal escape' => ["1.21.0+14.g4531440\x1b[31m"];
    }
}
