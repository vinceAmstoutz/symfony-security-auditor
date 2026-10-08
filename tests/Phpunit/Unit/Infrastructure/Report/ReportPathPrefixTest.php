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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPathPrefix;

final class ReportPathPrefixTest extends TestCase
{
    #[DataProvider('prefixesThatNameNoFolder')]
    public function test_a_prefix_that_names_no_folder_leaves_the_path_as_it_is(?string $prefix): void
    {
        self::assertSame('src/A.php', (new ReportPathPrefix($prefix))->apply('src/A.php'));
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function prefixesThatNameNoFolder(): iterable
    {
        yield 'no prefix' => [null];
        yield 'an empty prefix' => [''];
        yield 'blanks' => ['   '];
        yield 'the current directory' => ['.'];
        yield 'the current directory with a separator' => ['./'];
        yield 'the root separator' => ['/'];
    }

    #[DataProvider('prefixes')]
    public function test_it_puts_the_folder_the_project_lives_in_before_the_path(string $prefix, string $expected): void
    {
        self::assertSame($expected, (new ReportPathPrefix($prefix))->apply('src/A.php'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function prefixes(): iterable
    {
        yield 'a folder' => ['backend', 'backend/src/A.php'];
        yield 'nested folders' => ['apps/shop', 'apps/shop/src/A.php'];
        yield 'a trailing separator' => ['apps/shop/', 'apps/shop/src/A.php'];
        yield 'a leading separator' => ['/apps/shop', 'apps/shop/src/A.php'];
        yield 'a leading current directory' => ['./apps/shop', 'apps/shop/src/A.php'];
        yield 'several leading current directories' => ['././apps/shop', 'apps/shop/src/A.php'];
        yield 'blanks around it' => ['  apps/shop  ', 'apps/shop/src/A.php'];
        yield 'backslashes' => ['apps\\shop\\', 'apps/shop/src/A.php'];
    }
}
