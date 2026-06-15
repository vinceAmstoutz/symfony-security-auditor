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

use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Serializer\Encoder\JsonDecode;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ContextAwareAttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\InvalidCacheConfigurationException;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class FilesystemAttackerCache implements ContextAwareAttackerCacheInterface
{
    public function __construct(
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
        private string $keySalt = '',
        private JsonEncoder $jsonEncoder = new JsonEncoder(),
    ) {
        if (u($cacheDir)->trim()->isEmpty()) {
            throw InvalidCacheConfigurationException::forEmptyCacheDir();
        }
    }

    public function get(array $chunk): ?array
    {
        return $this->getForContext($chunk, '');
    }

    public function store(array $chunk, array $rawVulnerabilities): void
    {
        $this->storeForContext($chunk, '', $rawVulnerabilities);
    }

    public function getForContext(array $chunk, string $contextKey): ?array
    {
        $path = $this->pathForChunk($chunk, $contextKey);

        if (!$this->filesystem->exists($path)) {
            return null;
        }

        try {
            $raw = $this->filesystem->readFile($path);

            $decoded = $this->jsonEncoder->decode($raw, JsonEncoder::FORMAT, [JsonDecode::ASSOCIATIVE => true]);
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
        } catch (NotEncodableValueException $notEncodableValueException) {
            $this->logger->warning('Attacker cache entry was unreadable, ignoring', [
                'path' => $path,
                'error' => $notEncodableValueException->getMessage(),
            ]);

            return null;
        }
    }

    public function storeForContext(array $chunk, string $contextKey, array $rawVulnerabilities): void
    {
        $path = $this->pathForChunk($chunk, $contextKey);

        try {
            $encoded = $this->jsonEncoder->encode($rawVulnerabilities, JsonEncoder::FORMAT, [JsonEncode::OPTIONS => \JSON_UNESCAPED_SLASHES]);
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
    private function pathForChunk(array $chunk, string $contextKey): string
    {
        $key = $this->keyForChunk($chunk, $contextKey);

        return \sprintf('%s/%s/%s.json', u($this->cacheDir)->trimEnd('/')->toString(), u($key)->slice(0, 2)->toString(), $key);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function keyForChunk(array $chunk, string $contextKey): string
    {
        $signatures = [];
        foreach ($chunk as $file) {
            $signatures[] = $file->relativePath().'='.$file->contentHash();
        }

        sort($signatures);

        $payload = implode("\n", $signatures);
        if ('' !== $this->keySalt) {
            $payload = $this->keySalt."\0".$payload;
        }

        if ('' !== $contextKey) {
            $payload .= "\0context:".$contextKey;
        }

        return hash('sha256', $payload);
    }
}
