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

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;

final class FilesystemAttackerCacheTest extends TestCase
{
    private string $cacheDir;

    private FilesystemAttackerCache $filesystemAttackerCache;

    public function test_get_returns_null_when_no_entry_exists(): void
    {
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];

        self::assertNull($this->filesystemAttackerCache->get($chunk));
    }

    public function test_round_trip_store_and_get_returns_same_payload(): void
    {
        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php echo "a";')];
        $payload = [['type' => 'sql_injection', 'severity' => 'high', 'title' => 't']];

        $this->filesystemAttackerCache->store($chunk, $payload);

        self::assertSame($payload, $this->filesystemAttackerCache->get($chunk));
    }

    public function test_round_trip_preserves_all_entries_for_multi_finding_payload(): void
    {
        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php echo "a";')];
        $payload = [
            ['type' => 'sql_injection', 'severity' => 'high', 'title' => 'one'],
            ['type' => 'broken_access_control', 'severity' => 'medium', 'title' => 'two'],
            ['type' => 'missing_csrf_protection', 'severity' => 'low', 'title' => 'three'],
        ];

        $this->filesystemAttackerCache->store($chunk, $payload);

        self::assertSame($payload, $this->filesystemAttackerCache->get($chunk));
    }

    public function test_get_returns_null_for_chunk_with_modified_content(): void
    {
        $original = [ProjectFile::create('a.php', '/app/a.php', 'one')];
        $modified = [ProjectFile::create('a.php', '/app/a.php', 'two')];

        $this->filesystemAttackerCache->store($original, [['type' => 'sql_injection', 'severity' => 'high']]);

        self::assertNull($this->filesystemAttackerCache->get($modified));
    }

    public function test_key_is_independent_of_chunk_order(): void
    {
        $projectFile = ProjectFile::create('a.php', '/app/a.php', 'A');
        $b = ProjectFile::create('b.php', '/app/b.php', 'B');
        $payload = [['type' => 'sql_injection', 'severity' => 'high']];

        $this->filesystemAttackerCache->store([$projectFile, $b], $payload);

        self::assertSame($payload, $this->filesystemAttackerCache->get([$b, $projectFile]));
    }

    public function test_get_returns_null_when_cache_file_is_invalid_json(): void
    {
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];
        $payload = [['type' => 'sql_injection']];

        $this->filesystemAttackerCache->store($chunk, $payload);

        $files = glob($this->cacheDir.'/*/*.json') ?: [];
        self::assertNotEmpty($files);
        file_put_contents($files[0], 'not json{{{');

        self::assertNull($this->filesystemAttackerCache->get($chunk));
    }

    public function test_get_returns_null_when_cache_file_contains_non_array_json(): void
    {
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];
        $payload = [['type' => 'sql_injection']];

        $this->filesystemAttackerCache->store($chunk, $payload);

        $files = glob($this->cacheDir.'/*/*.json') ?: [];
        file_put_contents($files[0], '"a string"');

        self::assertNull($this->filesystemAttackerCache->get($chunk));
    }

    public function test_constructor_rejects_empty_cache_dir(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new FilesystemAttackerCache('   ', new Filesystem(), new NullLogger());
    }

    public function test_get_logs_warning_when_cache_entry_is_unreadable_json(): void
    {
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];
        $this->filesystemAttackerCache->store($chunk, [['type' => 'sql_injection']]);

        $files = glob($this->cacheDir.'/*/*.json') ?: [];
        file_put_contents($files[0], '{{{');

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg) use (&$warnings): void {
                $warnings[] = $msg;
            },
        );
        $logger->method('debug');

        $filesystemAttackerCache = new FilesystemAttackerCache($this->cacheDir, new Filesystem(), $logger);

        self::assertNull($filesystemAttackerCache->get($chunk));
        self::assertContains('Attacker cache entry was unreadable, ignoring', $warnings);
    }

    public function test_store_creates_nested_shard_directory_from_key_prefix(): void
    {
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];

        $this->filesystemAttackerCache->store($chunk, [['type' => 'sql_injection']]);

        $files = glob($this->cacheDir.'/*/*.json') ?: [];
        self::assertCount(1, $files);
        $relative = substr($files[0], \strlen($this->cacheDir) + 1);
        self::assertMatchesRegularExpression('#^[a-f0-9]{2}/[a-f0-9]{64}\.json$#', $relative);
    }

    public function test_store_writes_file_at_path_derived_from_sha256_of_relative_path_and_content_hash(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', 'X');

        $expectedSignature = 'src/A.php='.hash('sha256', 'X');
        $expectedKey = hash('sha256', $expectedSignature);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedKey, 0, 2), $expectedKey);

        $this->filesystemAttackerCache->store([$projectFile], [['type' => 'sql_injection']]);

        self::assertFileExists($expectedPath);
    }

    public function test_two_files_with_identical_content_but_different_paths_use_distinct_cache_entries(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', 'SAME');
        $b = ProjectFile::create('src/B.php', '/app/src/B.php', 'SAME');

        $this->filesystemAttackerCache->store([$projectFile], [['type' => 'sql_injection', 'title' => 'a-finding']]);
        $this->filesystemAttackerCache->store([$b], [['type' => 'sql_injection', 'title' => 'b-finding']]);

        self::assertSame([['type' => 'sql_injection', 'title' => 'a-finding']], $this->filesystemAttackerCache->get([$projectFile]));
        self::assertSame([['type' => 'sql_injection', 'title' => 'b-finding']], $this->filesystemAttackerCache->get([$b]));
    }

    public function test_dump_path_has_trailing_slash_stripped_from_cache_dir(): void
    {
        $capturedPath = '';
        $filesystem = $this->createMock(Filesystem::class);
        $filesystem->method('dumpFile')->willReturnCallback(
            static function (string $path) use (&$capturedPath): void {
                $capturedPath = $path;
            },
        );

        $filesystemAttackerCache = new FilesystemAttackerCache($this->cacheDir.'/', $filesystem, new NullLogger());
        $projectFile = ProjectFile::create('a.php', '/app/a.php', '<?php');

        $filesystemAttackerCache->store([$projectFile], [['type' => 'sql_injection']]);

        self::assertStringNotContainsString('//', $capturedPath);
    }

    public function test_get_logs_debug_cache_hit_with_path(): void
    {
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];

        $this->filesystemAttackerCache->store($chunk, [['type' => 'sql_injection']]);

        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $filesystemAttackerCache = new FilesystemAttackerCache($this->cacheDir, new Filesystem(), $logger);
        $filesystemAttackerCache->get($chunk);

        $hitLogs = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => 'Attacker cache hit' === $entry[0],
        ));

        self::assertCount(1, $hitLogs);
        self::assertArrayHasKey('path', $hitLogs[0][1]);
    }

    public function test_store_logs_debug_stored_with_path(): void
    {
        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $filesystemAttackerCache = new FilesystemAttackerCache($this->cacheDir, new Filesystem(), $logger);
        $filesystemAttackerCache->store([ProjectFile::create('a.php', '/app/a.php', '<?php')], [['type' => 'sql_injection']]);

        $storedLogs = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => 'Attacker cache stored' === $entry[0],
        ));

        self::assertCount(1, $storedLogs);
        self::assertArrayHasKey('path', $storedLogs[0][1]);
    }

    public function test_store_failure_warning_includes_path_and_error_keys(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $filesystemAttackerCache = new FilesystemAttackerCache('/proc/cannot-write', new Filesystem(), $logger);
        $filesystemAttackerCache->store([ProjectFile::create('a.php', '/app/a.php', '<?php')], [['type' => 'sql_injection']]);

        $failureLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Failed to write attacker cache entry' === $entry[0],
        ));

        self::assertCount(1, $failureLogs);
        self::assertArrayHasKey('path', $failureLogs[0][1]);
        self::assertArrayHasKey('error', $failureLogs[0][1]);
        self::assertNotSame('', $failureLogs[0][1]['error']);
    }

    public function test_get_failure_warning_includes_path_and_error_keys(): void
    {
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];
        $this->filesystemAttackerCache->store($chunk, [['type' => 'sql_injection']]);

        $files = glob($this->cacheDir.'/*/*.json') ?: [];
        file_put_contents($files[0], '{{{');

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $filesystemAttackerCache = new FilesystemAttackerCache($this->cacheDir, new Filesystem(), $logger);
        $filesystemAttackerCache->get($chunk);

        $unreadableLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Attacker cache entry was unreadable, ignoring' === $entry[0],
        ));

        self::assertCount(1, $unreadableLogs);
        self::assertArrayHasKey('path', $unreadableLogs[0][1]);
        self::assertArrayHasKey('error', $unreadableLogs[0][1]);
        self::assertNotSame('', $unreadableLogs[0][1]['error']);
    }

    public function test_store_calls_mkdir_to_create_shard_directory(): void
    {
        $filesystem = $this->createMock(Filesystem::class);
        $filesystem->expects(self::once())->method('mkdir');
        $filesystem->method('dumpFile');

        $filesystemAttackerCache = new FilesystemAttackerCache($this->cacheDir, $filesystem, new NullLogger());
        $filesystemAttackerCache->store([ProjectFile::create('a.php', '/app/a.php', '<?php')], [['type' => 'sql_injection']]);
    }

    public function test_store_with_unwritable_dir_logs_warning_and_does_not_throw(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg) use (&$warnings): void {
                $warnings[] = $msg;
            },
        );
        $logger->method('debug');

        $filesystemAttackerCache = new FilesystemAttackerCache('/proc/cannot-write-here', new Filesystem(), $logger);
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];

        $filesystemAttackerCache->store($chunk, [['type' => 'sql_injection']]);

        self::assertContains('Failed to write attacker cache entry', $warnings);
    }

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir().'/attacker_cache_'.uniqid('', true);
        $this->filesystemAttackerCache = new FilesystemAttackerCache($this->cacheDir, new Filesystem(), new NullLogger());
    }

    protected function tearDown(): void
    {
        $filesystem = new Filesystem();
        if ($filesystem->exists($this->cacheDir)) {
            $filesystem->remove($this->cacheDir);
        }
    }
}
