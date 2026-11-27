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
use VinceAmstoutz\SymfonySecurityAuditor\Command\FileUrl;

final class FileUrlTest extends TestCase
{
    #[DataProvider('paths')]
    public function test_it_writes_a_path_as_a_file_url_a_browser_opens(string $path, string $url): void
    {
        self::assertSame($url, FileUrl::of($path));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function paths(): iterable
    {
        yield 'an absolute POSIX path' => ['/tmp/report.html', 'file:///tmp/report.html'];
        yield 'a space and a percent sign' => ['/tmp/my dir/100%.html', 'file:///tmp/my%20dir/100%25.html'];
        yield 'a Windows drive path' => ['C:\\Users\\Ann Lee\\AppData\\Local\\Temp\\report.html', 'file:///C:/Users/Ann%20Lee/AppData/Local/Temp/report.html'];
    }
}
