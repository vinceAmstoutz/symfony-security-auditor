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

use InvalidArgumentException;
use JsonException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Filesystem;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;

final readonly class FilesystemAttackerCache implements AttackerCacheInterface
{
    public function __construct(
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
    ) {
        if ('' === trim($cacheDir)) {
            throw new InvalidArgumentException('Attacker cache dir cannot be empty');
        }
    }

    public function get(array $chunk): ?array
    {
        $path = $this->pathForChunk($chunk);

        if (!$this->filesystem->exists($path)) {
            return null;
        }

        try {
            $raw = file_get_contents($path);
            if (false === $raw) {
                return null;
            }

            // Raw json_decode (over symfony/serializer) is deliberate: cache stores opaque
            // vulnerability dicts that VulnerabilityFactory::fromList() tolerates partially,
            // so we want array hydration only, no class-targeted decoding.
            $decoded = json_decode($raw, true, flags: \JSON_THROW_ON_ERROR);
            if (!\is_array($decoded)) {
                return null;
            }

            $this->logger->debug('Attacker cache hit', ['path' => $path]);

            return $this->coerceToEntries($decoded);
        } catch (JsonException $jsonException) {
            $this->logger->warning('Attacker cache entry was unreadable, ignoring', [
                'path' => $path,
                'error' => $jsonException->getMessage(),
            ]);

            return null;
        }
    }

    public function store(array $chunk, array $rawVulnerabilities): void
    {
        $path = $this->pathForChunk($chunk);

        try {
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
    private function pathForChunk(array $chunk): string
    {
        $key = $this->keyForChunk($chunk);

        return \sprintf('%s/%s/%s.json', rtrim($this->cacheDir, '/'), substr($key, 0, 2), $key);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function keyForChunk(array $chunk): string
    {
        $signatures = [];
        foreach ($chunk as $file) {
            $signatures[] = $file->relativePath().'='.$file->contentHash();
        }

        sort($signatures);

        return hash('sha256', implode("\n", $signatures));
    }
}
