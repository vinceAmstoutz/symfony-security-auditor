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
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Throwable;

use function Symfony\Component\String\u;

/**
 * Decorator over `ComposerAuditRunnerInterface` that persists the JSON payload
 * across audit runs, keyed by a SHA-256 hash of the project's `composer.lock`.
 *
 * Hit: the cached JSON is returned without ever spawning composer.
 * Miss / no lockfile: delegates to the inner runner, caches the result on
 * success (only when a lockfile exists), and either way returns the raw JSON.
 *
 * Cache I/O failures degrade gracefully — they are logged and swallowed so the
 * audit never aborts because of a stale or unreadable advisory cache entry.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LockfileHashedAdvisoryCache implements ComposerAuditRunnerInterface
{
    public function __construct(
        private ComposerAuditRunnerInterface $composerAuditRunner,
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
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
        $lockfilePath = u($projectPath)->trimEnd('/')->toString().'/composer.lock';

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

        if (!$this->filesystem->exists($path)) {
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

    private function writeCache(string $hash, string $json): void
    {
        $path = $this->pathForHash($hash);

        try {
            $this->filesystem->mkdir(\dirname($path));
            $this->filesystem->dumpFile($path, $json);
            $this->logger->debug('Advisory cache stored', ['lockfile_hash' => $hash]);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write advisory cache entry', [
                'path' => $path,
                'error' => $throwable->getMessage(),
            ]);
        }
    }
}
