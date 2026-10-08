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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\WritableFilePath;

final class WritableFilePathTest extends TestCase
{
    private string $tmpDir;

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

    public function test_a_file_that_does_not_exist_yet_can_be_written(): void
    {
        self::assertTrue(WritableFilePath::canBeWritten($this->tmpDir.'/report.json'));
    }

    public function test_an_existing_regular_file_can_be_written(): void
    {
        file_put_contents($this->tmpDir.'/report.json', 'previous run');

        self::assertTrue(WritableFilePath::canBeWritten($this->tmpDir.'/report.json'));
    }

    public function test_an_existing_directory_cannot_be_written(): void
    {
        self::assertFalse(WritableFilePath::canBeWritten($this->tmpDir));
    }

    public function test_an_existing_pipe_cannot_be_written(): void
    {
        posix_mkfifo($this->tmpDir.'/report.pipe', 0o600);

        self::assertFalse(WritableFilePath::canBeWritten($this->tmpDir.'/report.pipe'));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/writable_file_path_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }
}
