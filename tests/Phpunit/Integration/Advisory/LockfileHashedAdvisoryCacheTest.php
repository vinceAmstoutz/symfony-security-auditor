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
use PHPUnit\Framework\Attributes\DataProvider;
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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\FileSystem\Fixture\AssertsOwnerOnlyAccessTrait;

final class LockfileHashedAdvisoryCacheTest extends TestCase
{
    use AssertsOwnerOnlyAccessTrait;

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
    public function test_a_lockfile_symlinked_to_a_file_inside_the_project_is_cached_like_any_other(): void
    {
        file_put_contents($this->projectDir.'/real.lock', '{"lock": "v1"}');
        symlink($this->projectDir.'/real.lock', $this->projectDir.'/composer.lock');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        $lockfileHashedAdvisoryCache->run($this->projectDir);
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame(1, $recordingComposerAuditRunner->callCount, 'a lockfile symlinked inside the project is keyed by its content, so the second call is a hit');
        self::assertFileExists($this->cacheDir.'/'.substr(hash('sha256', '{"lock": "v1"}'), 0, 2).'/'.hash('sha256', '{"lock": "v1"}').'.json');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_a_lockfile_symlinked_outside_the_project_is_never_cached(): void
    {
        $outside = sys_get_temp_dir().'/advisory_cache_outside_'.uniqid('', true).'.lock';
        file_put_contents($outside, '{"lock": "v1"}');
        symlink($outside, $this->projectDir.'/composer.lock');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        try {
            $lockfileHashedAdvisoryCache->run($this->projectDir);
            $lockfileHashedAdvisoryCache->run($this->projectDir);
        } finally {
            unlink($outside);
        }

        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'a lockfile symlinked outside the project must reach the inner runner every time');
        $cacheFiles = glob($this->cacheDir.'/*/*.json');
        self::assertSame([], false !== $cacheFiles ? $cacheFiles : []);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    #[DataProvider('payloadsThatAreNotAnAdvisoryDocument')]
    public function test_a_payload_that_is_not_an_advisory_document_is_returned_but_never_cached(string $payload): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $recordingComposerAuditRunner = $this->recordingRunner($payload);
        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        $first = $lockfileHashedAdvisoryCache->run($this->projectDir);
        $second = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame($payload, $first);
        self::assertSame($payload, $second);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'a payload no advisory lookup can use must not be served from cache');
        $cacheFiles = glob($this->cacheDir.'/*/*.json');
        self::assertSame([], false !== $cacheFiles ? $cacheFiles : []);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function payloadsThatAreNotAnAdvisoryDocument(): iterable
    {
        yield 'text before the JSON document' => ["Warning: something on stdout\n{\"advisories\": {}}"];
        yield 'invalid JSON' => ['not json at all'];
        yield 'a scalar' => ['42'];
        yield 'null' => ['null'];
        yield 'no advisories key' => ['{"abandoned": {}}'];
        yield 'advisories that is not a map' => ['{"advisories": "none"}'];
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

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_expiry_is_computed_from_the_injected_clock_even_when_it_diverges_from_the_real_wall_clock(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $mockClock = new MockClock('2000-01-01T00:00:00Z');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        $lockfileHashedAdvisoryCache = $this->makeCacheWithClock($recordingComposerAuditRunner, $mockClock);
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $mockClock->modify('+25 hours');
        $recordingComposerAuditRunner->payload = '{"advisories": {"new/cve": []}}';
        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"new/cve": []}}', $json);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'an entry past the TTL per the injected clock must expire regardless of the real OS wall-clock time recorded on the cache file');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_read_through_symlinked_cache_entry_logs_a_warning_with_the_full_path_context(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedHash, 0, 2), $expectedHash);

        $outsideTarget = sys_get_temp_dir().'/advisory_cache_symlink_target_'.uniqid('', true);
        file_put_contents($outsideTarget, 'ORIGINAL');
        mkdir(\dirname($expectedPath), recursive: true);
        symlink($outsideTarget, $expectedPath);

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );
        $logger->method('debug');

        try {
            $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
                $this->recordingRunner('{"advisories": {"foo/bar": []}}'),
                $this->cacheDir,
                new Filesystem(),
                $logger,
                new NativeClock(),
            );
            $lockfileHashedAdvisoryCache->run($this->projectDir);

            $symlinkWarnings = array_values(array_filter(
                $warnings,
                static fn (array $entry): bool => 'Refusing to read advisory cache entry through symlinked path, falling back to live audit' === $entry[0],
            ));
            self::assertCount(1, $symlinkWarnings);
            self::assertSame(['path' => $expectedPath], $symlinkWarnings[0][1]);
        } finally {
            unlink($outsideTarget);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_expired_cache_entry_logs_a_debug_with_the_full_path_context(): void
    {
        $lockfileContent = '{"lock": "v1"}';
        $this->writeLockfile($lockfileContent);
        $expectedHash = hash('sha256', $lockfileContent);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedHash, 0, 2), $expectedHash);

        $mockClock = new MockClock('2000-01-01T00:00:00Z');
        $this->makeCacheWithClock($this->recordingRunner('{"advisories": {"foo/bar": []}}'), $mockClock)->run($this->projectDir);

        $debugMessages = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $message, array $context = []) use (&$debugMessages): void {
                $debugMessages[] = [$message, $context];
            },
        );

        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache(
            $this->recordingRunner('{"advisories": {"new/cve": []}}'),
            $this->cacheDir,
            new Filesystem(),
            $logger,
            $mockClock,
        );

        $mockClock->modify('+25 hours');
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $expiredLogs = array_values(array_filter(
            $debugMessages,
            static fn (array $entry): bool => 'Advisory cache entry expired, falling back to live audit' === $entry[0],
        ));
        self::assertCount(1, $expiredLogs);
        self::assertSame(['path' => $expectedPath], $expiredLogs[0][1]);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_cache_entry_aged_exactly_the_ttl_is_treated_as_expired(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $mockClock = new MockClock('2000-01-01T00:00:00Z');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        $lockfileHashedAdvisoryCache = $this->makeCacheWithClock($recordingComposerAuditRunner, $mockClock);
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $mockClock->modify('+24 hours');
        $recordingComposerAuditRunner->payload = '{"advisories": {"new/cve": []}}';
        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"new/cve": []}}', $json);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'an entry aged exactly the TTL must be treated as expired, not served from cache');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_refuses_its_own_directory_below_the_cache_root_when_that_is_a_symlink(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $base = sys_get_temp_dir().'/advisory_cache_symlinked_self_'.uniqid('', true);
        mkdir($base.'/elsewhere', recursive: true);
        mkdir($base.'/cache');
        symlink($base.'/elsewhere', $base.'/cache/advisory');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache($recordingComposerAuditRunner, $base.'/cache/advisory', new Filesystem(), new NullLogger(), new NativeClock());

        try {
            $lockfileHashedAdvisoryCache->run($this->projectDir);
            $lockfileHashedAdvisoryCache->run($this->projectDir);

            self::assertSame(2, $recordingComposerAuditRunner->callCount);
            self::assertSame(['.', '..'], scandir($base.'/elsewhere'));
        } finally {
            (new Filesystem())->remove($base);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_a_relative_cache_directory_is_read_against_the_working_directory(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $base = sys_get_temp_dir().'/advisory_cache_relative_'.uniqid('', true);
        mkdir($base);
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);

        chdir($base);
        try {
            $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache($recordingComposerAuditRunner, 'var/cache/advisory', new Filesystem(), new NullLogger(), new NativeClock());
            $lockfileHashedAdvisoryCache->run($this->projectDir);
            $lockfileHashedAdvisoryCache->run($this->projectDir);

            self::assertSame(1, $recordingComposerAuditRunner->callCount);
        } finally {
            chdir($workingDirectory);
            (new Filesystem())->remove($base);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_still_caches_when_a_directory_above_the_cache_is_a_symlink(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $base = sys_get_temp_dir().'/advisory_cache_symlinked_parent_'.uniqid('', true);
        mkdir($base.'/real', recursive: true);
        symlink($base.'/real', $base.'/link');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $lockfileHashedAdvisoryCache = new LockfileHashedAdvisoryCache($recordingComposerAuditRunner, $base.'/link/cache', new Filesystem(), new NullLogger(), new NativeClock());
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);

        chdir($base);
        try {
            $lockfileHashedAdvisoryCache->run($this->projectDir);
            $lockfileHashedAdvisoryCache->run($this->projectDir);

            self::assertSame(1, $recordingComposerAuditRunner->callCount);
        } finally {
            chdir($workingDirectory);
            (new Filesystem())->remove($base);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_a_stored_payload_and_the_directories_made_for_it_are_owner_only(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        $this->makeCache($this->recordingRunner('{"advisories": {}}'))->run($this->projectDir);

        $entries = glob($this->cacheDir.'/*/*.json');
        self::assertIsArray($entries);
        self::assertCount(1, $entries);
        self::assertOwnerOnlyFile($entries[0]);
        self::assertOwnerOnlyDirectory(\dirname($entries[0]));
        self::assertOwnerOnlyDirectory($this->cacheDir);
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
