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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache;

use JsonException;
use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ContextAwareAttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\InvalidCacheConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\UnsafeCacheWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PrivateFileWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class FilesystemAttackerCache implements ContextAwareAttackerCacheInterface
{
    /**
     * @throws InvalidCacheConfigurationException
     */
    public function __construct(
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
        private string $keySalt = '',
    ) {
        if (u($cacheDir)->trim()->isEmpty()) {
            throw InvalidCacheConfigurationException::forEmptyCacheDir('Attacker');
        }
    }

    #[Override]
    public function get(array $chunk): ?array
    {
        return $this->getForContext($chunk, '');
    }

    #[Override]
    public function store(array $chunk, array $rawVulnerabilities): void
    {
        $this->storeForContext($chunk, '', $rawVulnerabilities);
    }

    #[Override]
    public function getForContext(array $chunk, string $contextKey): ?array
    {
        $path = $this->pathForChunk($chunk, $contextKey);

        if (!$this->filesystem->exists($path)) {
            return null;
        }

        if ($this->isSymlinkedPath($path)) {
            $this->logger->warning('Attacker cache entry path was a symlink, ignoring', ['path' => $path]);

            return null;
        }

        try {
            $raw = $this->filesystem->readFile($path);

            $decoded = json_decode($raw, true, flags: \JSON_THROW_ON_ERROR);
            if (!\is_array($decoded)) {
                return null;
            }

            $this->logger->debug('Attacker cache hit', ['path' => $path]);

            return $this->coerceToEntries($decoded);
        } catch (IOException $ioException) {
            $this->logger->warning('Attacker cache entry was unreadable, ignoring', [
                'path' => $path,
                'error' => $ioException->getMessage(),
            ]);

            return null;
        } catch (JsonException $jsonException) {
            $this->logger->warning('Attacker cache entry was unreadable, ignoring', [
                'path' => $path,
                'error' => $jsonException->getMessage(),
            ]);

            return null;
        }
    }

    #[Override]
    public function storeForContext(array $chunk, string $contextKey, array $rawVulnerabilities): void
    {
        $path = $this->pathForChunk($chunk, $contextKey);

        try {
            $this->assertSafeToWrite($path);
            $encoded = json_encode($rawVulnerabilities, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
            PrivateFileWriter::write($this->filesystem, $path, $encoded);
            $this->logger->debug('Attacker cache stored', ['path' => $path]);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write attacker cache entry', [
                'path' => $path,
                'error' => $throwable->getMessage(),
            ]);
        }
    }

    /**
     * Refuses a path through a symlink: the path derives from the audited
     * project's files, so a planted link would redirect the write.
     *
     * @throws UnsafeCacheWriteException
     */
    private function assertSafeToWrite(string $path): void
    {
        if ($this->isSymlinkedPath($path)) {
            throw UnsafeCacheWriteException::forSymlinkedPath($path);
        }
    }

    /**
     * Trusts the cache directory and every directory above it, on read and on
     * write.
     */
    private function isSymlinkedPath(string $path): bool
    {
        return SymlinkGuard::isThroughSymlink($path, $this->cacheDir);
    }

    /**
     * @param array<int|string, mixed> $decoded
     *
     * @return array<int, array<string, mixed>>
     */
    private function coerceToEntries(array $decoded): array
    {
        $entries = [];
        foreach ($decoded as $entry) {
            if (!\is_array($entry)) {
                continue;
            }

            $stringKeyed = [];
            foreach ($entry as $key => $value) {
                $stringKeyed[(string) $key] = $value;
            }

            $entries[] = $stringKeyed;
        }

        return $entries;
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function pathForChunk(array $chunk, string $contextKey): string
    {
        $key = $this->keyForChunk($chunk, $contextKey);

        return \sprintf('%s/%s/%s.json', u($this->cacheDir)->trimEnd('/')->toString(), u($key)->slice(0, 2)->toString(), $key);
    }

    /**
     * Hashes each file's signature on its own, so a crafted path holding the
     * separators cannot give one chunk another chunk's key.
     *
     * @param list<ProjectFile> $chunk
     */
    private function keyForChunk(array $chunk, string $contextKey): string
    {
        $signatures = [];
        foreach ($chunk as $file) {
            $signatures[] = hash('sha256', \sprintf('%s=%s', $file->relativePath(), $file->contentHash()));
        }

        sort($signatures);

        $payload = implode("\n", $signatures);
        if ('' !== $this->keySalt) {
            $payload = \sprintf("%s\0%s", $this->keySalt, $payload);
        }

        if ('' !== $contextKey) {
            $payload = \sprintf("%s\0context:%s", $payload, $contextKey);
        }

        return hash('sha256', $payload);
    }
}
