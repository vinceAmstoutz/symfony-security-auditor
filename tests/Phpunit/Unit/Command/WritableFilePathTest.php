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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\WritableFilePath;

final class WritableFilePathTest extends TestCase
{
    #[DataProvider('paths')]
    public function test_it_tells_a_path_naming_a_directory_from_a_file_path(string $path, bool $namesADirectory): void
    {
        self::assertSame($namesADirectory, WritableFilePath::namesADirectory($path));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function paths(): iterable
    {
        yield 'a file' => ['reports/report.json', false];
        yield 'a trailing slash' => ['reports/', true];
        yield 'a trailing backslash' => ['reports\\', true];
        yield 'a file whose name is not UTF-8' => ["reports/r\xFF.json", false];
        yield 'a directory whose name is not UTF-8' => ["reports\xFF/", true];
    }
}
