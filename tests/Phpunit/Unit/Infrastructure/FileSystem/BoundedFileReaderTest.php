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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\BoundedFileReader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\UnreadableInputFileException;

final class BoundedFileReaderTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/bounded_reader_test_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws UnreadableInputFileException
     */
    public function test_it_reads_a_file_of_thirty_two_mebibytes_whole(): void
    {
        $path = $this->tmpDir.'/full.json';
        $contents = '['.str_repeat(' ', 33_554_430).']';
        $this->filesystem->dumpFile($path, $contents);

        self::assertSame($contents, BoundedFileReader::read($path));
    }

    /**
     * @throws UnreadableInputFileException
     */
    public function test_it_refuses_a_file_one_byte_past_thirty_two_mebibytes(): void
    {
        $path = $this->tmpDir.'/oversized.json';
        $this->filesystem->dumpFile($path, '['.str_repeat(' ', 33_554_431).']');

        $this->expectException(UnreadableInputFileException::class);
        $this->expectExceptionMessage(\sprintf('File "%s" holds more than 33554432 bytes, so it was not read.', $path));

        BoundedFileReader::read($path);
    }

    /**
     * @throws UnreadableInputFileException
     */
    public function test_it_stops_reading_a_link_to_a_device_that_never_ends(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $this->filesystem->symlink('/dev/zero', $path);

        $this->expectException(UnreadableInputFileException::class);
        $this->expectExceptionMessage(\sprintf('File "%s" holds more than 33554432 bytes, so it was not read.', $path));

        BoundedFileReader::read($path);
    }

    /**
     * @throws UnreadableInputFileException
     */
    public function test_it_refuses_a_directory_it_reads_nothing_from(): void
    {
        $this->expectException(UnreadableInputFileException::class);
        $this->expectExceptionMessage(\sprintf('File "%s" could not be read: file_get_contents(): Read of', $this->tmpDir));

        BoundedFileReader::read($this->tmpDir);
    }

    /**
     * @throws UnreadableInputFileException
     */
    public function test_it_refuses_a_missing_file_with_the_reason(): void
    {
        $path = $this->tmpDir.'/absent.json';

        $this->expectException(UnreadableInputFileException::class);
        $this->expectExceptionMessage(\sprintf('File "%1$s" could not be read: file_get_contents(%1$s): Failed to open stream: No such file or directory', $path));

        BoundedFileReader::read($path);
    }

    /**
     * @throws UnreadableInputFileException
     */
    public function test_the_error_handler_in_place_before_reading_is_back_afterwards(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($path, '[]');
        $received = [];
        set_error_handler(static function (int $severity, string $message) use (&$received): bool {
            $received[] = $message;

            return true;
        });

        try {
            BoundedFileReader::read($path);
            trigger_error('after reading', \E_USER_WARNING);
        } finally {
            restore_error_handler();
        }

        self::assertSame(['after reading'], $received);
    }
}
