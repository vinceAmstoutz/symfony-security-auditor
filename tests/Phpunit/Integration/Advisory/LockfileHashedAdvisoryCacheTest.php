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
use Psr\Log\NullLogger;
use RuntimeException;
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
