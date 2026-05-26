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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\History;

use JsonException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AuditHistoryStoreInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\History\Exception\InvalidHistoryDirectoryException;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class FilesystemAuditHistoryStore implements AuditHistoryStoreInterface
{
    public function __construct(
        private string $historyDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
    ) {
        if ('' === trim($historyDir)) {
            throw InvalidHistoryDirectoryException::forEmptyDir();
        }
    }

    public function loadFingerprints(string $projectIdentifier): array
    {
        $path = $this->pathFor($projectIdentifier);

        if (!$this->filesystem->exists($path)) {
            return [];
        }

        try {
            $raw = $this->filesystem->readFile($path);
            $decoded = json_decode($raw, true, flags: \JSON_THROW_ON_ERROR);
        } catch (IOException $ioException) {
            $this->logger->warning('Audit history entry unreadable, treating as empty', [
                'path' => $path,
                'error' => $ioException->getMessage(),
            ]);

            return [];
        } catch (JsonException $jsonException) {
            $this->logger->warning('Audit history entry was not valid JSON, treating as empty', [
                'path' => $path,
                'error' => $jsonException->getMessage(),
            ]);

            return [];
        }

        if (!\is_array($decoded) || !isset($decoded['fingerprints']) || !\is_array($decoded['fingerprints'])) {
            return [];
        }

        return array_values(array_filter(
            $decoded['fingerprints'],
            static fn (mixed $entry): bool => \is_string($entry) && '' !== $entry,
        ));
    }

    public function storeFingerprints(string $projectIdentifier, array $fingerprints): void
    {
        $path = $this->pathFor($projectIdentifier);

        try {
            $payload = json_encode(
                ['fingerprints' => $fingerprints],
                \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_PRETTY_PRINT,
            );
            $this->filesystem->dumpFile($path, $payload);
        } catch (IOException $ioException) {
            $this->logger->warning('Could not persist audit history (continuing without)', [
                'path' => $path,
                'error' => $ioException->getMessage(),
            ]);
        } catch (JsonException $jsonException) {
            $this->logger->warning('Could not encode audit history (continuing without)', [
                'path' => $path,
                'error' => $jsonException->getMessage(),
            ]);
        }
    }

    private function pathFor(string $projectIdentifier): string
    {
        return \sprintf('%s/%s.json', rtrim($this->historyDir, '/'), $this->safeFilename($projectIdentifier));
    }

    private function safeFilename(string $projectIdentifier): string
    {
        return substr(hash('sha256', $projectIdentifier), 0, 16);
    }
}
