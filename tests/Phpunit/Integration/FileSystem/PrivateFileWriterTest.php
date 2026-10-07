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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\FileSystem;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PrivateFileWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\FileSystem\Fixture\AssertsOwnerOnlyAccessTrait;

final class PrivateFileWriterTest extends TestCase
{
    use AssertsOwnerOnlyAccessTrait;

    private string $root;

    public function test_it_writes_the_content(): void
    {
        PrivateFileWriter::write(new Filesystem(), $this->root.'/entry.json', '{"a":1}');

        self::assertSame('{"a":1}', file_get_contents($this->root.'/entry.json'));
    }

    public function test_the_file_it_creates_is_owner_only(): void
    {
        PrivateFileWriter::write(new Filesystem(), $this->root.'/entry.json', 'x');

        self::assertOwnerOnlyFile($this->root.'/entry.json');
    }

    public function test_every_directory_it_creates_is_owner_only(): void
    {
        PrivateFileWriter::write(new Filesystem(), $this->root.'/shard/deeper/entry.json', 'x');

        self::assertOwnerOnlyDirectory($this->root.'/shard');
        self::assertOwnerOnlyDirectory($this->root.'/shard/deeper');
    }

    public function test_a_directory_that_already_exists_keeps_its_permissions(): void
    {
        PrivateFileWriter::write(new Filesystem(), $this->root.'/entry.json', 'x');

        self::assertSame('0755', self::permissionsOf($this->root));
    }

    public function test_a_file_that_already_exists_is_tightened_and_replaced(): void
    {
        $path = $this->root.'/entry.json';
        $filesystem = new Filesystem();
        $filesystem->dumpFile($path, 'old');
        $filesystem->chmod($path, 0o644);

        PrivateFileWriter::write($filesystem, $path, 'new');

        self::assertSame('new', file_get_contents($path));
        self::assertOwnerOnlyFile($path);
    }

    public function test_the_file_is_owner_only_before_its_content_is_written(): void
    {
        $filesystem = new class extends Filesystem {
            public ?string $permissionsAtDumpFileStart = null;

            /**
             * @param resource|string $content
             */
            #[Override]
            public function dumpFile(string $filename, $content): void
            {
                $this->permissionsAtDumpFileStart = file_exists($filename) ? substr(\sprintf('%o', (int) fileperms($filename)), -4) : null;
                parent::dumpFile($filename, $content);
            }
        };

        PrivateFileWriter::write($filesystem, $this->root.'/entry.json', 'x');

        self::assertSame('0600', $filesystem->permissionsAtDumpFileStart);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir().'/private_file_writer_'.uniqid('', true);
        mkdir($this->root, 0o755, true);
        chmod($this->root, 0o755);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->root);
    }
}
