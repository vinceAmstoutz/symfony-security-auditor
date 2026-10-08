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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\WindowsDrivePath;

final class WindowsDrivePathTest extends TestCase
{
    #[DataProvider('pathCases')]
    public function test_it_gives_a_windows_drive_path_one_spelling_and_leaves_any_other_path_alone(string $path, string $expected): void
    {
        self::assertSame($expected, WindowsDrivePath::normalize($path));
    }

    /** @return iterable<string, array{string, string}> */
    public static function pathCases(): iterable
    {
        yield 'forward slashes' => ['C:/proj/src/A.php', 'C:/proj/src/A.php'];
        yield 'backslashes' => ['C:\proj\src\A.php', 'C:/proj/src/A.php'];
        yield 'mixed separators' => ['C:\proj/src\A.php', 'C:/proj/src/A.php'];
        yield 'a URI path with a leading slash' => ['/C:/proj/src/A.php', 'C:/proj/src/A.php'];
        yield 'a lower-case drive letter' => ['c:/proj/src/A.php', 'C:/proj/src/A.php'];
        yield 'a lower-case drive letter after a leading slash' => ['/c:/proj/src/A.php', 'C:/proj/src/A.php'];
        yield 'a trailing separator' => ['C:\proj\\', 'C:/proj'];
        yield 'dot segments' => ['C:/proj/lib/../src/./A.php', 'C:/proj/src/A.php'];
        yield 'a drive without a separator is not a drive path' => ['C:proj', 'C:proj'];
        yield 'a POSIX absolute path' => ['/app/src/A.php', '/app/src/A.php'];
        yield 'a POSIX path with a trailing separator' => ['/app/', '/app/'];
        yield 'a relative path' => ['src/A.php', 'src/A.php'];
        yield 'a relative path with dot segments' => ['./src/../src/A.php', './src/../src/A.php'];
        yield 'a UNIX file name holding a backslash' => ['src/a\b.php', 'src/a\b.php'];
        yield 'a UNIX path whose first segment is a drive-like letter and a colon' => ['/c/proj/A.php', '/c/proj/A.php'];
    }
}
