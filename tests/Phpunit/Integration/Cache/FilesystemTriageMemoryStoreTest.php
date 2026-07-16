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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Cache;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\InvalidCacheConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemTriageMemoryStore;

final class FilesystemTriageMemoryStoreTest extends TestCase
{
    private string $memoryPath;

    private FilesystemTriageMemoryStore $filesystemTriageMemoryStore;

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_feedback_is_empty_when_no_entry_exists(): void
    {
        self::assertTrue($this->filesystemTriageMemoryStore->feedback()->isEmpty());
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_a_recorded_rejection_is_surfaced_as_feedback(): void
    {
        $this->filesystemTriageMemoryStore->record('sql_injection', 'src/A.php', 'Injectable query', 'input is bound via a prepared statement');

        $feedback = $this->filesystemTriageMemoryStore->feedback();

        self::assertEquals(
            [new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Injectable query', 'input is bound via a prepared statement')],
            $feedback->entries,
        );
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_recording_the_same_finding_again_replaces_its_reason_instead_of_duplicating(): void
    {
        $this->filesystemTriageMemoryStore->record('sql_injection', 'src/A.php', 'Injectable query', 'first reason');
        $this->filesystemTriageMemoryStore->record('sql_injection', 'src/A.php', 'Injectable query', 'second, more precise reason');

        $feedback = $this->filesystemTriageMemoryStore->feedback();

        self::assertEquals(
            [new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Injectable query', 'second, more precise reason')],
            $feedback->entries,
        );
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_recording_a_different_finding_keeps_both_entries(): void
    {
        $this->filesystemTriageMemoryStore->record('sql_injection', 'src/A.php', 'Injectable query', 'reason A');
        $this->filesystemTriageMemoryStore->record('xxe', 'src/B.php', 'XML parsing', 'reason B');

        self::assertCount(2, $this->filesystemTriageMemoryStore->feedback()->entries);
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_recording_more_than_the_entry_cap_drops_the_oldest_entries(): void
    {
        $filesystemTriageMemoryStore = new FilesystemTriageMemoryStore($this->memoryPath, $this->filesystem(), new NullLogger(), 2);

        $filesystemTriageMemoryStore->record('sql_injection', 'src/File0.php', 'title', 'reason');
        $filesystemTriageMemoryStore->record('sql_injection', 'src/File1.php', 'title', 'reason');
        $filesystemTriageMemoryStore->record('sql_injection', 'src/File2.php', 'title', 'reason');

        $entries = $filesystemTriageMemoryStore->feedback()->entries;

        self::assertSame(['src/File2.php', 'src/File1.php'], array_map(static fn (AcceptedFindingFeedback $acceptedFindingFeedback): string => $acceptedFindingFeedback->file, $entries));
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_feedback_surfaces_the_newest_rejections_first(): void
    {
        $this->filesystemTriageMemoryStore->record('sql_injection', 'src/Old.php', 'title', 'older reason');
        $this->filesystemTriageMemoryStore->record('xxe', 'src/New.php', 'title', 'newer reason');

        $files = array_map(
            static fn (AcceptedFindingFeedback $acceptedFindingFeedback): string => $acceptedFindingFeedback->file,
            $this->filesystemTriageMemoryStore->feedback()->entries,
        );

        self::assertSame(['src/New.php', 'src/Old.php'], $files);
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_a_recorded_reason_is_capped_before_it_is_persisted(): void
    {
        $this->filesystemTriageMemoryStore->record('sql_injection', 'src/A.php', 'title', str_repeat('a', FilesystemTriageMemoryStore::MAX_REASON_LENGTH + 500));

        $entries = $this->filesystemTriageMemoryStore->feedback()->entries;

        self::assertCount(1, $entries);
        self::assertSame(FilesystemTriageMemoryStore::MAX_REASON_LENGTH, mb_strlen($entries[0]->reason));
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_an_entry_without_a_reason_is_not_surfaced_as_feedback(): void
    {
        $this->filesystem()->dumpFile($this->memoryPath, json_encode([
            ['type' => 'sql_injection', 'file' => 'src/A.php', 'title' => 'T'],
        ], \JSON_THROW_ON_ERROR));

        self::assertTrue($this->filesystemTriageMemoryStore->feedback()->isEmpty());
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_a_malformed_memory_file_is_treated_as_empty(): void
    {
        $this->filesystem()->dumpFile($this->memoryPath, 'not json {{{');

        self::assertTrue($this->filesystemTriageMemoryStore->feedback()->isEmpty());
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_a_memory_file_that_is_not_a_json_array_is_treated_as_empty(): void
    {
        $this->filesystem()->dumpFile($this->memoryPath, json_encode(['not' => 'a list'], \JSON_THROW_ON_ERROR));

        self::assertTrue($this->filesystemTriageMemoryStore->feedback()->isEmpty());
    }

    /**
     * A malicious contributor could pre-plant a symlink at the exact
     * (config-fixed) memory path, turning a routine audit run into an
     * arbitrary-file write.
     *
     * @throws InvalidCacheConfigurationException
     */
    public function test_record_refuses_to_write_through_a_symlinked_memory_file(): void
    {
        $outsideTarget = sys_get_temp_dir().'/triage_memory_symlink_target_'.uniqid('', true);
        file_put_contents($outsideTarget, 'ORIGINAL');
        mkdir(\dirname($this->memoryPath), recursive: true);
        symlink($outsideTarget, $this->memoryPath);

        try {
            $this->filesystemTriageMemoryStore->record('sql_injection', 'src/A.php', 'T', 'reason');

            self::assertSame('ORIGINAL', file_get_contents($outsideTarget));
        } finally {
            unlink($outsideTarget);
        }
    }

    /**
     * Mirrors the write-side guard: reading through a pre-planted symlink
     * would trust its content as a genuine, previously-recorded entry.
     *
     * @throws InvalidCacheConfigurationException
     */
    public function test_feedback_refuses_to_read_through_a_symlinked_memory_file(): void
    {
        $outsideTarget = sys_get_temp_dir().'/triage_memory_symlink_read_target_'.uniqid('', true);
        file_put_contents($outsideTarget, json_encode([
            ['type' => 'sql_injection', 'file' => 'src/A.php', 'title' => 'T', 'reason' => 'planted'],
        ], \JSON_THROW_ON_ERROR));
        mkdir(\dirname($this->memoryPath), recursive: true);
        symlink($outsideTarget, $this->memoryPath);

        try {
            self::assertTrue($this->filesystemTriageMemoryStore->feedback()->isEmpty());
        } finally {
            unlink($outsideTarget);
        }
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_record_logs_the_path_and_error_and_does_not_throw_when_the_write_fails(): void
    {
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturn(false);
        $filesystem->method('dumpFile')->willThrowException(new IOException('disk full'));

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $filesystemTriageMemoryStore = new FilesystemTriageMemoryStore($this->memoryPath, $filesystem, $logger);
        $filesystemTriageMemoryStore->record('sql_injection', 'src/A.php', 'T', 'reason');

        self::assertTrue($filesystemTriageMemoryStore->feedback()->isEmpty());
        self::assertSame([['Failed to write triage memory entry', ['path' => $this->memoryPath, 'error' => 'disk full']]], $warnings);
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_record_logs_the_path_when_refusing_a_symlinked_memory_file(): void
    {
        $outsideTarget = sys_get_temp_dir().'/triage_memory_symlink_log_target_'.uniqid('', true);
        file_put_contents($outsideTarget, 'ORIGINAL');
        mkdir(\dirname($this->memoryPath), recursive: true);
        symlink($outsideTarget, $this->memoryPath);

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        try {
            (new FilesystemTriageMemoryStore($this->memoryPath, $this->filesystem(), $logger))->record('sql_injection', 'src/A.php', 'T', 'reason');
        } finally {
            unlink($outsideTarget);
        }

        self::assertSame([['Triage memory path was a symlink, skipping write', ['path' => $this->memoryPath]]], $warnings);
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_feedback_logs_the_path_and_error_when_the_file_cannot_be_read(): void
    {
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturn(true);
        $filesystem->method('readFile')->willThrowException(new IOException('permission denied'));

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $feedback = (new FilesystemTriageMemoryStore($this->memoryPath, $filesystem, $logger))->feedback();

        self::assertTrue($feedback->isEmpty());
        self::assertSame([['Triage memory file was unreadable, ignoring', ['path' => $this->memoryPath, 'error' => 'permission denied']]], $warnings);
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_constructor_rejects_an_empty_path(): void
    {
        $this->expectException(InvalidCacheConfigurationException::class);

        new FilesystemTriageMemoryStore('', new Filesystem(), new NullLogger());
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->memoryPath = sys_get_temp_dir().'/triage_memory_'.uniqid('', true).'/memory.json';
        $this->filesystemTriageMemoryStore = new FilesystemTriageMemoryStore($this->memoryPath, $this->filesystem(), new NullLogger());
    }

    #[Override]
    protected function tearDown(): void
    {
        $filesystem = $this->filesystem();
        if ($filesystem->exists(\dirname($this->memoryPath))) {
            $filesystem->remove(\dirname($this->memoryPath));
        }
    }

    private function filesystem(): Filesystem
    {
        return new Filesystem();
    }
}
