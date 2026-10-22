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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\OutermostDirectories;

final class OutermostDirectoriesTest extends TestCase
{
    /**
     * @param list<string> $directories
     * @param list<string> $expected
     */
    #[DataProvider('listedDirectories')]
    public function test_it_keeps_each_directory_no_other_listed_one_holds_once_in_the_order_listed(array $directories, array $expected): void
    {
        self::assertSame($expected, OutermostDirectories::of($directories));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>}>
     */
    public static function listedDirectories(): iterable
    {
        yield 'unrelated directories' => [['/p/src', '/p/config', '/p/templates'], ['/p/src', '/p/config', '/p/templates']];
        yield 'a directory inside the one before it' => [['/p/src', '/p/src/Controller'], ['/p/src']];
        yield 'a directory inside the one after it' => [['/p/src/Controller', '/p/src'], ['/p/src']];
        yield 'a directory two levels inside another' => [['/p/src', '/p/config', '/p/src/Controller/Admin'], ['/p/src', '/p/config']];
        yield 'the project folder holds every other' => [['/p/src', '/p', '/p/config'], ['/p']];
        yield 'a sibling sharing a name prefix' => [['/p/src', '/p/src-extra', '/p/srcAdmin'], ['/p/src', '/p/src-extra', '/p/srcAdmin']];
        yield 'one directory listed twice' => [['/p/src', '/p/config', '/p/src'], ['/p/src', '/p/config']];
        yield 'one directory spelled two ways' => [['/p/src/', '/p/./src', '/p/config/../src'], ['/p/src']];
        yield 'a directory spelled with dot segments inside another' => [['/p/src', '/p/config/../src/Controller'], ['/p/src']];
        yield 'the filesystem root holds every other' => [['/p/src', '/', '/q'], ['/']];
        yield 'a folder ending with a colon spelled with two slashes' => [['/p/a:/Admin', '/p/a://'], ['/p/a://']];
    }
}
