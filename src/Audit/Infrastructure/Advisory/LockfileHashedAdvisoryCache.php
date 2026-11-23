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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\MalformedAdvisoryPayloadException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\UnsafeAdvisoryCacheWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PrivateFileWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;

use function Symfony\Component\String\u;

/**
 * Caches the decorated runner's advisory JSON for `TTL_SECONDS`, keyed by the
 * SHA-256 of the project's `composer.lock`. Caches nothing without a lockfile.
 * A cache I/O failure is logged and never fails the audit.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class LockfileHashedAdvisoryCache implements ComposerAuditRunnerInterface
{
    public const int TTL_SECONDS = 86_400;

    private LockfileHasher $lockfileHasher;

    public function __construct(
        private ComposerAuditRunnerInterface $composerAuditRunner,
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
        private ClockInterface $clock,
    ) {
        $this->lockfileHasher = new LockfileHasher($filesystem, $logger);
    }

    #[Override]
    public function run(string $projectPath): string
    {
        $lockfileHash = $this->lockfileHasher->hash($projectPath);

        if (null !== $lockfileHash) {
            $cachedJson = $this->readCache($lockfileHash);
            if (null !== $cachedJson) {
                $this->logger->debug('Advisory cache hit', ['lockfile_hash' => $lockfileHash]);

                return $cachedJson;
            }
        }

        $json = $this->composerAuditRunner->run($projectPath);

        if (null !== $lockfileHash && $this->isAdvisoryDocument($json)) {
            $this->writeCache($lockfileHash, $json);
        }

        return $json;
    }

    private function isAdvisoryDocument(string $json): bool
    {
        try {
            AdvisoryPayload::fromJson($json);
        } catch (MalformedAdvisoryPayloadException) {
            return false;
        }

        return true;
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
            PrivateFileWriter::write($this->filesystem, $path, $json);
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
     * Refuses a path through a symlink: the path derives from the untrusted
     * project's `composer.lock`, so a planted link would redirect the write.
     *
     * @throws UnsafeAdvisoryCacheWriteException
     */
    private function assertSafeToWrite(string $path): void
    {
        if ($this->isUnsafePath($path)) {
            throw UnsafeAdvisoryCacheWriteException::forSymlinkedPath($path);
        }
    }

    /**
     * Trusts the parent of the cache directory and every directory above it.
     */
    private function isUnsafePath(string $path): bool
    {
        return SymlinkGuard::isThroughSymlink($path, \dirname($this->cacheDir));
    }
}
