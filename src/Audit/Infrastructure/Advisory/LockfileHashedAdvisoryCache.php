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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Override;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\UnsafeAdvisoryCacheWriteException;

use function Symfony\Component\String\u;

/**
 * Decorator over `ComposerAuditRunnerInterface` that persists the JSON payload
 * across audit runs, keyed by a SHA-256 hash of the project's `composer.lock`.
 *
 * Hit: the cached JSON is returned without ever spawning composer, provided
 * the entry is younger than `TTL_SECONDS` — the lockfile hash alone cannot
 * detect newly-disclosed advisories against an unchanged dependency set.
 * Miss / stale / no lockfile: delegates to the inner runner, caches the
 * result on success (only when a lockfile exists), and either way returns
 * the raw JSON.
 *
 * Cache I/O failures degrade gracefully — they are logged and swallowed so the
 * audit never aborts because of a stale or unreadable advisory cache entry.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LockfileHashedAdvisoryCache implements ComposerAuditRunnerInterface
{
    /**
     * Advisory feeds gain new CVEs over time for an unchanged dependency set,
     * so even a lockfile-hash hit must expire — 24 hours balances staying
     * useful within a single working day against missing newly-disclosed
     * advisories for longer than necessary.
     */
    private const int TTL_SECONDS = 86_400;

    public function __construct(
        private ComposerAuditRunnerInterface $composerAuditRunner,
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
        private ClockInterface $clock,
    ) {}

    #[Override]
    public function run(string $projectPath): string
    {
        $lockfileHash = $this->lockfileHash($projectPath);

        if (null !== $lockfileHash) {
            $cachedJson = $this->readCache($lockfileHash);
            if (null !== $cachedJson) {
                $this->logger->debug('Advisory cache hit', ['lockfile_hash' => $lockfileHash]);

                return $cachedJson;
            }
        }

        $json = $this->composerAuditRunner->run($projectPath);

        if (null !== $lockfileHash) {
            $this->writeCache($lockfileHash, $json);
        }

        return $json;
    }

    private function lockfileHash(string $projectPath): ?string
    {
        $lockfilePath = \sprintf('%s/composer.lock', u($projectPath)->trimEnd('/')->toString());

        if (!$this->filesystem->exists($lockfilePath)) {
            return null;
        }

        try {
            $contents = $this->filesystem->readFile($lockfilePath);
        } catch (IOException $ioException) {
            $this->logger->warning('composer.lock present but unreadable; skipping advisory cache', [
                'path' => $lockfilePath,
                'error' => $ioException->getMessage(),
            ]);

            return null;
        }

        return hash('sha256', $contents);
    }

    private function pathForHash(string $hash): string
    {
        return \sprintf('%s/%s/%s.json', u($this->cacheDir)->trimEnd('/')->toString(), u($hash)->slice(0, 2)->toString(), $hash);
    }

    private function readCache(string $hash): ?string
    {
        $path = $this->pathForHash($hash);

        if ($this->isUnsafePath($path)) {
            $this->logger->warning('Refusing to read advisory cache entry through symlinked path, falling back to live audit', [
                'path' => $path,
            ]);

            return null;
        }

        if (!$this->filesystem->exists($path)) {
            return null;
        }

        if ($this->isExpired($path)) {
            $this->logger->debug('Advisory cache entry expired, falling back to live audit', ['path' => $path]);

            return null;
        }

        try {
            return $this->filesystem->readFile($path);
        } catch (IOException $ioException) {
            $this->logger->warning('Advisory cache entry unreadable, falling back to live audit', [
                'path' => $path,
                'error' => $ioException->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * `filemtime()` only fails for a path that does not exist, and every
     * caller has already confirmed existence via `Filesystem::exists()`
     * immediately before calling this — asserted rather than branched on,
     * since the only way to fail it is a TOCTOU race no test can force.
     */
    private function isExpired(string $path): bool
    {
        $modifiedAt = filemtime($path);
        \assert(false !== $modifiedAt, 'filemtime() must succeed for a path exists() already confirmed present');

        return $this->clock->now()->getTimestamp() - $modifiedAt >= self::TTL_SECONDS;
    }

    private function writeCache(string $hash, string $json): void
    {
        $path = $this->pathForHash($hash);

        try {
            $this->assertSafeToWrite($path);
            $this->filesystem->mkdir(\dirname($path));
            $this->filesystem->dumpFile($path, $json);
            // Stamped via $this->clock, not left to the OS, so isExpired()'s subtraction never mixes two different time sources.
            $this->filesystem->touch($path, $this->clock->now()->getTimestamp());
            $this->logger->debug('Advisory cache stored', ['lockfile_hash' => $hash]);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write advisory cache entry', [
                'path' => $path,
                'error' => $throwable->getMessage(),
            ]);
        }
    }

    /**
     * `Filesystem::dumpFile()` transparently writes through a symlink at its
     * destination, and `Filesystem::mkdir()` treats a symlinked directory as
     * already existing — a cache path derived entirely from the project's own
     * `composer.lock` content lets a malicious contributor pre-plant a symlink
     * at the exact path this cache will write to, turning a routine audit run
     * into an arbitrary-file overwrite.
     *
     * @throws UnsafeAdvisoryCacheWriteException
     */
    private function assertSafeToWrite(string $path): void
    {
        if ($this->isUnsafePath($path)) {
            throw UnsafeAdvisoryCacheWriteException::forSymlinkedPath($path);
        }
    }

    private function isUnsafePath(string $path): bool
    {
        return is_link($path) || is_link(\dirname($path));
    }
}
