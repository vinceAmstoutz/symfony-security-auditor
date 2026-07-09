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

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
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
            $this->filesystem->mkdir(\dirname($path));
            $this->filesystem->dumpFile($path, $encoded);
            $this->logger->debug('Attacker cache stored', ['path' => $path]);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write attacker cache entry', [
                'path' => $path,
                'error' => $throwable->getMessage(),
            ]);
        }
    }

    /**
     * `Filesystem::dumpFile()` transparently writes through a symlink at its
     * destination, and `Filesystem::mkdir()` treats a symlinked directory as
     * already existing — a cache path derived entirely from attacker-visible
     * content (a project file's own path/content, folded through a key salt
     * built from the target's own bundle config) lets a malicious contributor
     * pre-plant a symlink at the exact path this cache will write to, turning
     * a routine audit run into an arbitrary-file overwrite.
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
     * Mirrors {@see self::assertSafeToWrite()}'s check for the read side —
     * `Filesystem::readFile()` also transparently follows a symlink, so the
     * same pre-planted symlink that would otherwise corrupt a write turns an
     * ordinary cache read into an arbitrary-file read whose content is
     * trusted as a real, previously-computed finding.
     */
    private function isSymlinkedPath(string $path): bool
    {
        return is_link($path) || is_link(\dirname($path));
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
     * A scanned file's path comes from the audited project's filesystem, not
     * from us — a crafted relative path embedding another file's own
     * `path=hash` signature plus a newline can make a single-file chunk's
     * raw signature string byte-identical to a real multi-file chunk's
     * joined signatures. Hashing each file's signature individually first
     * fixes every field to 64 hex characters, which can never contain the
     * `=`/newline separators, so no crafted path can bleed into another
     * file's field or forge an extra one.
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
