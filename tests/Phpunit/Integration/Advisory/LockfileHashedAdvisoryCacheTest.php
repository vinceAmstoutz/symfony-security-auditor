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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture\RecordingComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture\ThrowingComposerAuditRunner;

final class LockfileHashedAdvisoryCacheTest extends TestCase
{
    private string $projectDir;

    private string $cacheDir;

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_runs_inner_and_persists_result_on_first_call(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"foo/bar": []}}', $json);
        self::assertSame(1, $recordingComposerAuditRunner->callCount);
        $cacheFiles = glob($this->cacheDir.'/*/*.json');
        self::assertGreaterThan(0, \count(false !== $cacheFiles ? $cacheFiles : []));
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_missing_lockfile_does_not_emit_an_unreadable_warning(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = $message;
            },
        );

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $this->recordingRunner('{"advisories": {}}'),
            $this->cacheDir,
            new Filesystem(),
            $logger,
            new NativeClock(),
        );

        $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame([], $warnings);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_returns_cached_payload_without_invoking_inner(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');
        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $secondJson = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"foo/bar": []}}', $secondJson);
        self::assertSame(1, $recordingComposerAuditRunner->callCount, 'second call must be served from cache');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_cache_hit_emits_advisory_cache_hit_debug_log_with_lockfile_hash_context(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);

        $debugMessages = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $message, array $context = []) use (&$debugMessages): void {
                $debugMessages[] = [$message, $context];
            },
        );

        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        // Prime the cache with the default logger so the first run does not pollute the recording one.
        $this->makeCache($recordingComposerAuditRunner)->run($this->projectDir);

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $recordingComposerAuditRunner,
            $this->cacheDir,
            new Filesystem(),
            $logger,
            new NativeClock(),
        );
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $hitLogs = array_values(array_filter(
            $debugMessages,
            static fn (array $entry): bool => 'Advisory cache hit' === $entry[0],
        ));
        self::assertCount(1, $hitLogs);
        self::assertSame($expectedHash, $hitLogs[0][1]['lockfile_hash']);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_different_lockfile_contents_produce_distinct_cache_entries(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');
        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $this->writeLockfile('{"lock": "v2"}');
        $recordingComposerAuditRunner->payload = '{"advisories": {"baz/qux": []}}';

        $secondJson = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"baz/qux": []}}', $secondJson);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'lock content change must miss the cache');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_falls_back_to_inner_when_no_lockfile_exists(): void
    {
        // No composer.lock written intentionally
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        $first = $lockfileHashedAdvisoryCache->run($this->projectDir);
        $second = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {}}', $first);
        self::assertSame('{"advisories": {}}', $second);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'without a lockfile, every call must hit the inner runner');
        $cacheFiles = glob($this->cacheDir.'/*/*.json');
        self::assertSame([], false !== $cacheFiles ? $cacheFiles : []);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_does_not_persist_when_inner_throws(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $throwingComposerAuditRunner = new ThrowingComposerAuditRunner();

        $lockfileHashedAdvisoryCache = $this->makeCache($throwingComposerAuditRunner);

        $this->expectException(RuntimeException::class);

        try {
            $lockfileHashedAdvisoryCache->run($this->projectDir);
        } finally {
            $cacheFiles = glob($this->cacheDir.'/*/*.json');
            self::assertSame([], false !== $cacheFiles ? $cacheFiles : []);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_falls_back_to_live_audit_when_lockfile_read_throws_io_exception(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturn(true);
        $filesystem->method('readFile')->willThrowException(new IOException('permission denied'));

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );
        $logger->method('debug');

        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $recordingComposerAuditRunner,
            $this->cacheDir,
            $filesystem,
            $logger,
            new NativeClock(),
        );

        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {}}', $json);
        self::assertSame(1, $recordingComposerAuditRunner->callCount, 'inner runner must still be called when the lockfile is unreadable');

        $unreadableLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'composer.lock present but unreadable; skipping advisory cache' === $entry[0],
        ));
        self::assertCount(1, $unreadableLogs);
        self::assertSame($this->projectDir.'/composer.lock', $unreadableLogs[0][1]['path']);
        self::assertSame('permission denied', $unreadableLogs[0][1]['error']);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_cache_miss_when_existing_entry_is_unreadable_and_falls_back_to_inner(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        // First run: real filesystem populates the cache.
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $this->makeCache($recordingComposerAuditRunner)->run($this->projectDir);

        // Second run: replace the filesystem with one that throws on readFile of any
        // path other than composer.lock, forcing the readCache() catch branch.
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturn(true);
        $lockfilePath = $this->projectDir.'/composer.lock';
        $filesystem->method('readFile')->willReturnCallback(
            static function (string $path) use ($lockfilePath): string {
                if ($path === $lockfilePath) {
                    return '{"lock": "v1"}';
                }

                throw new IOException('cache entry unreadable');
            },
        );

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );
        $logger->method('debug');

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $recordingComposerAuditRunner,
            $this->cacheDir,
            $filesystem,
            $logger,
            new NativeClock(),
        );

        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {}}', $json);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'inner runner must be called again after an unreadable cache entry');

        $unreadableLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Advisory cache entry unreadable, falling back to live audit' === $entry[0],
        ));
        self::assertCount(1, $unreadableLogs);
        $path = $unreadableLogs[0][1]['path'] ?? null;
        self::assertIsString($path);
        self::assertStringEndsWith('.json', $path);
        self::assertStringContainsString($this->cacheDir, $path);
        self::assertSame('cache entry unreadable', $unreadableLogs[0][1]['error'] ?? null);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_cache_file_is_written_at_two_char_shard_directory_under_full_hash_filename(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);

        $lockfileHashedAdvisoryCache = $this->makeCache($this->recordingRunner('{"advisories": {}}'));
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $globResult = glob($this->cacheDir.'/*/*.json');
        $files = false !== $globResult ? $globResult : [];
        self::assertCount(1, $files);

        $expectedPath = \sprintf(
            '%s/%s/%s.json',
            $this->cacheDir,
            substr($expectedHash, 0, 2),
            $expectedHash,
        );
        self::assertSame($expectedPath, $files[0]);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_write_refuses_to_write_through_a_dangling_symlinked_cache_file(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedHash, 0, 2), $expectedHash);

        $outsideTarget = sys_get_temp_dir().'/advisory_cache_symlink_target_'.uniqid('', true);
        mkdir(\dirname($expectedPath), recursive: true);
        symlink($outsideTarget, $expectedPath);

        try {
            $lockfileHashedAdvisoryCache = $this->makeCache($this->recordingRunner('{"advisories": {"foo/bar": []}}'));
            $lockfileHashedAdvisoryCache->run($this->projectDir);

            self::assertFileDoesNotExist($outsideTarget);
        } finally {
            if (file_exists($outsideTarget)) {
                unlink($outsideTarget);
            }
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_read_refuses_to_return_content_through_a_symlinked_cache_file(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedHash, 0, 2), $expectedHash);

        $outsideTarget = sys_get_temp_dir().'/advisory_cache_symlink_target_'.uniqid('', true);
        file_put_contents($outsideTarget, 'ORIGINAL');
        mkdir(\dirname($expectedPath), recursive: true);
        symlink($outsideTarget, $expectedPath);

        try {
            $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');
            $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

            $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

            self::assertSame('{"advisories": {"foo/bar": []}}', $json);
            self::assertSame(1, $recordingComposerAuditRunner->callCount, 'a symlinked cache entry must not be served as a hit');
            self::assertSame('ORIGINAL', file_get_contents($outsideTarget));
        } finally {
            unlink($outsideTarget);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_write_refuses_to_write_through_a_symlinked_shard_directory(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);
        $shardDir = \sprintf('%s/%s', $this->cacheDir, substr($expectedHash, 0, 2));

        $outsideDir = sys_get_temp_dir().'/advisory_cache_symlink_dir_'.uniqid('', true);
        mkdir($outsideDir);
        mkdir($this->cacheDir, recursive: true);
        symlink($outsideDir, $shardDir);

        try {
            $lockfileHashedAdvisoryCache = $this->makeCache($this->recordingRunner('{"advisories": {"foo/bar": []}}'));
            $lockfileHashedAdvisoryCache->run($this->projectDir);

            $globResult = glob($outsideDir.'/*.json');
            self::assertSame([], false !== $globResult ? $globResult : []);
        } finally {
            $filesystem = new Filesystem();
            $filesystem->remove($outsideDir);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_cache_dir_with_trailing_slash_is_normalized_before_assembling_path(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        $capturedDumpPaths = [];
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturnCallback(
            static fn (string $path): bool => str_ends_with($path, 'composer.lock'),
        );
        $filesystem->method('readFile')->willReturn('{"lock": "v1"}');
        $filesystem->method('dumpFile')->willReturnCallback(
            static function (string $path) use (&$capturedDumpPaths): void {
                $capturedDumpPaths[] = $path;
            },
        );

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $this->recordingRunner('{"advisories": {}}'),
            $this->cacheDir.'/',
            $filesystem,
            new NullLogger(),
            new NativeClock(),
        );
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertCount(1, $capturedDumpPaths);
        self::assertStringNotContainsString('//', $capturedDumpPaths[0]);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_write_failure_is_logged_and_does_not_propagate(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturnCallback(
            static fn (string $path): bool => str_ends_with($path, 'composer.lock'),
        );
        $filesystem->method('readFile')->willReturn('{"lock": "v1"}');
        $filesystem->method('mkdir')->willThrowException(new IOException('cache dir unwritable'));

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );
        $logger->method('debug');

        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $recordingComposerAuditRunner,
            $this->cacheDir,
            $filesystem,
            $logger,
            new NativeClock(),
        );

        // Must not throw despite the cache write failing.
        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"foo/bar": []}}', $json);

        $failureLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Failed to write advisory cache entry' === $entry[0],
        ));
        self::assertCount(1, $failureLogs);
        $path = $failureLogs[0][1]['path'] ?? null;
        self::assertIsString($path);
        self::assertStringEndsWith('.json', $path);
        self::assertSame('cache dir unwritable', $failureLogs[0][1]['error'] ?? null);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_successful_cache_write_emits_advisory_cache_stored_debug_log_with_lockfile_hash(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);

        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $message, array $context = []) use (&$debugLogs): void {
                $debugLogs[] = [$message, $context];
            },
        );

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $this->recordingRunner('{"advisories": {"foo/bar": []}}'),
            $this->cacheDir,
            new Filesystem(),
            $logger,
            new NativeClock(),
        );
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $storedLogs = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => 'Advisory cache stored' === $entry[0],
        ));
        self::assertCount(1, $storedLogs);
        self::assertSame($expectedHash, $storedLogs[0][1]['lockfile_hash'] ?? null);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_cache_entry_within_ttl_is_served_without_invoking_inner(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $mockClock = new MockClock();
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        $lockfileHashedAdvisoryCache = $this->makeCacheWithClock($recordingComposerAuditRunner, $mockClock);
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $mockClock->modify('+23 hours');
        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"foo/bar": []}}', $json);
        self::assertSame(1, $recordingComposerAuditRunner->callCount, 'an entry younger than the TTL must be served from cache');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_cache_entry_past_ttl_is_treated_as_a_miss(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $mockClock = new MockClock();
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        $lockfileHashedAdvisoryCache = $this->makeCacheWithClock($recordingComposerAuditRunner, $mockClock);
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $mockClock->modify('+25 hours');
        $recordingComposerAuditRunner->payload = '{"advisories": {"new/cve": []}}';
        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"new/cve": []}}', $json);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'an entry past the TTL must not be served from cache');
    }

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/advisory_cache_'.uniqid('', true);
        $this->cacheDir = $this->projectDir.'/cache';
        mkdir($this->projectDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        $filesystem = new Filesystem();
        if ($filesystem->exists($this->projectDir)) {
            $filesystem->remove($this->projectDir);
        }
    }

    private function writeLockfile(string $contents): void
    {
        file_put_contents($this->projectDir.'/composer.lock', $contents);
    }

    private function makeCache(ComposerAuditRunnerInterface $composerAuditRunner): LockfileHashedAdvisoryCache
    {
        return new LockfileHashedAdvisoryCache($composerAuditRunner, $this->cacheDir, new Filesystem(), new NullLogger(), new NativeClock());
    }

    private function makeCacheWithClock(ComposerAuditRunnerInterface $composerAuditRunner, ClockInterface $clock): LockfileHashedAdvisoryCache
    {
        return new LockfileHashedAdvisoryCache($composerAuditRunner, $this->cacheDir, new Filesystem(), new NullLogger(), $clock);
    }

    private function recordingRunner(string $payload): RecordingComposerAuditRunner
    {
        return new RecordingComposerAuditRunner($payload);
    }
}
