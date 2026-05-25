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

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture\RecordingComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture\ThrowingComposerAuditRunner;

final class LockfileHashedAdvisoryCacheTest extends TestCase
{
    private string $projectDir;

    private string $cacheDir;

    public function test_runs_inner_and_persists_result_on_first_call(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {"foo/bar": []}}');

        $lockfileHashedAdvisoryCache = $this->makeCache($recordingComposerAuditRunner);

        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"foo/bar": []}}', $json);
        self::assertSame(1, $recordingComposerAuditRunner->callCount);
        self::assertGreaterThan(0, \count(glob($this->cacheDir.'/*/*.json') ?: []));
    }

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

    public function test_cache_hit_emits_advisory_cache_hit_debug_log(): void
    {
        // Pins the `$this->logger->debug('Advisory cache hit', ...)` call against
        // MethodCallRemoval. Without an explicit assertion, the debug call can be
        // removed without any observable effect, leaving the mutant alive.
        $this->writeLockfile('{"lock": "v1"}');

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
        );
        $lockfileHashedAdvisoryCache->run($this->projectDir);

        $messages = array_column($debugMessages, 0);
        self::assertContains('Advisory cache hit', $messages);
    }

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
        self::assertSame([], glob($this->cacheDir.'/*/*.json') ?: []);
    }

    public function test_does_not_persist_when_inner_throws(): void
    {
        $this->writeLockfile('{"lock": "v1"}');
        $throwingComposerAuditRunner = new ThrowingComposerAuditRunner();

        $lockfileHashedAdvisoryCache = $this->makeCache($throwingComposerAuditRunner);

        $this->expectException(RuntimeException::class);

        try {
            $lockfileHashedAdvisoryCache->run($this->projectDir);
        } finally {
            self::assertSame([], glob($this->cacheDir.'/*/*.json') ?: []);
        }
    }

    public function test_falls_back_to_live_audit_when_lockfile_read_throws_io_exception(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        $filesystem = $this->createMock(Filesystem::class);
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
        );

        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {}}', $json);
        self::assertSame(1, $recordingComposerAuditRunner->callCount, 'inner runner must still be called when the lockfile is unreadable');
        $messages = array_column($warnings, 0);
        self::assertContains('composer.lock present but unreadable; skipping advisory cache', $messages);
    }

    public function test_cache_miss_when_existing_entry_is_unreadable_and_falls_back_to_inner(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        // First run: real filesystem populates the cache.
        $recordingComposerAuditRunner = $this->recordingRunner('{"advisories": {}}');
        $this->makeCache($recordingComposerAuditRunner)->run($this->projectDir);

        // Second run: replace the filesystem with one that throws on readFile of any
        // path other than composer.lock, forcing the readCache() catch branch.
        $filesystem = $this->createMock(Filesystem::class);
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
        );

        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {}}', $json);
        self::assertSame(2, $recordingComposerAuditRunner->callCount, 'inner runner must be called again after an unreadable cache entry');
        $messages = array_column($warnings, 0);
        self::assertContains('Advisory cache entry unreadable, falling back to live audit', $messages);
    }

    public function test_write_failure_is_logged_and_does_not_propagate(): void
    {
        $this->writeLockfile('{"lock": "v1"}');

        $filesystem = $this->createMock(Filesystem::class);
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
        );

        // Must not throw despite the cache write failing.
        $json = $lockfileHashedAdvisoryCache->run($this->projectDir);

        self::assertSame('{"advisories": {"foo/bar": []}}', $json);
        $messages = array_column($warnings, 0);
        self::assertContains('Failed to write advisory cache entry', $messages);
    }

    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/advisory_cache_'.uniqid('', true);
        $this->cacheDir = $this->projectDir.'/cache';
        mkdir($this->projectDir, 0o777, true);
    }

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
        return new LockfileHashedAdvisoryCache($composerAuditRunner, $this->cacheDir, new Filesystem(), new NullLogger());
    }

    private function recordingRunner(string $payload): RecordingComposerAuditRunner
    {
        return new RecordingComposerAuditRunner($payload);
    }
}
