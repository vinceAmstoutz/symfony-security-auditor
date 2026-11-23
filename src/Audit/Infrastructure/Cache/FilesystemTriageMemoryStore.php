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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\InvalidCacheConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PrivateFileWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;

use function Symfony\Component\String\u;

/**
 * The reviewer's rejections with a reason, kept across runs and given back to
 * the reviewer as feedback. Each audited project has its own file, keyed by a
 * hash of its path, so one project's rejections never reach another's review.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FilesystemTriageMemoryStore implements ReviewerFeedbackProviderInterface, TriageMemoryRecorderInterface
{
    /**
     * The oldest entries are dropped first.
     */
    public const int DEFAULT_MAX_ENTRIES = 500;

    /**
     * Caps a stored reason, which a later run replays into the reviewer's
     * system prompt.
     */
    public const int MAX_REASON_LENGTH = 5_000;

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function __construct(
        private string $directory,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
        private AuditedProjectPathHolder $auditedProjectPathHolder,
        private int $maxEntries = self::DEFAULT_MAX_ENTRIES,
    ) {
        if (u($directory)->trim()->isEmpty()) {
            throw InvalidCacheConfigurationException::forEmptyCacheDir('Triage memory');
        }
    }

    /**
     * Reads the holder on each call, never at construction, so the path the
     * command sets scopes the file.
     */
    private function path(): string
    {
        $projectScope = substr(hash('sha256', $this->auditedProjectPathHolder->path()), 0, 16);

        return \sprintf('%s/%s.json', $this->directory, $projectScope);
    }

    #[Override]
    public function feedback(): ReviewerFeedback
    {
        $entries = [];
        foreach ($this->readEntries() as $entry) {
            $feedbackEntry = $this->feedbackOf($entry);
            if ($feedbackEntry instanceof AcceptedFindingFeedback) {
                $entries[] = $feedbackEntry;
            }
        }

        return new ReviewerFeedback(array_reverse($entries));
    }

    #[Override]
    public function record(string $type, string $file, string $title, int $line, string $reason): void
    {
        $path = $this->path();
        if ($this->isSymlinkedPath($path)) {
            $this->logger->warning('Triage memory path was a symlink, skipping write', ['path' => $path]);

            return;
        }

        try {
            $entry = ['type' => $type, 'file' => $file, 'title' => $title, 'line' => $line, 'reason' => $this->cappedReason($reason)];
            $entries = $this->insertIfAbsent($this->readEntries(), $entry);
            $encoded = json_encode(\array_slice($entries, -$this->maxEntries), \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
            PrivateFileWriter::write($this->filesystem, $path, $encoded);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write triage memory entry', [
                'path' => $path,
                'error' => $throwable->getMessage(),
            ]);
        }
    }

    /**
     * @return list<array<array-key, mixed>>
     */
    private function readEntries(): array
    {
        $path = $this->path();
        if (!$this->filesystem->exists($path) || $this->isSymlinkedPath($path)) {
            return [];
        }

        try {
            $decoded = json_decode($this->filesystem->readFile($path), true, flags: \JSON_THROW_ON_ERROR);
        } catch (IOException|JsonException $exception) {
            $this->logger->warning('Triage memory file was unreadable, ignoring', [
                'path' => $path,
                'error' => $exception->getMessage(),
            ]);

            return [];
        }

        if (!\is_array($decoded) || !array_is_list($decoded)) {
            return [];
        }

        return $this->arrayEntriesOf($decoded);
    }

    /**
     * @param array<array-key, mixed> $decoded
     *
     * @return list<array<array-key, mixed>>
     */
    private function arrayEntriesOf(array $decoded): array
    {
        $entries = [];
        foreach ($decoded as $entry) {
            if (\is_array($entry)) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * Keeps the first recorded reason of a finding, so the
     * {@see ReviewerFeedback::digest()} the reviewer cache keys on stays stable.
     *
     * @param list<array<array-key, mixed>> $entries
     * @param array<array-key, mixed>       $newEntry
     *
     * @return list<array<array-key, mixed>>
     */
    private function insertIfAbsent(array $entries, array $newEntry): array
    {
        $key = $this->keyOf($newEntry);
        foreach ($entries as $entry) {
            if ($key === $this->keyOf($entry)) {
                return $entries;
            }
        }

        $entries[] = $newEntry;

        return $entries;
    }

    /**
     * Hashes each field on its own, so a separator in the model-written `file`
     * or `title` cannot make two findings share a key.
     *
     * @param array<array-key, mixed> $entry
     */
    private function keyOf(array $entry): string
    {
        return hash('sha256', implode('', [
            hash('sha256', $this->stringField($entry, 'type')),
            hash('sha256', $this->stringField($entry, 'file')),
            hash('sha256', $this->stringField($entry, 'title')),
            hash('sha256', (string) $this->intField($entry, 'line')),
        ]));
    }

    private function cappedReason(string $reason): string
    {
        return u($reason)->truncate(self::MAX_REASON_LENGTH)->toString();
    }

    /**
     * @param array<array-key, mixed> $entry
     */
    private function feedbackOf(array $entry): ?AcceptedFindingFeedback
    {
        $reason = $entry['reason'] ?? null;
        if (!\is_string($reason) || u($reason)->trim()->isEmpty()) {
            return null;
        }

        return new AcceptedFindingFeedback(
            $this->stringField($entry, 'type'),
            $this->stringField($entry, 'file'),
            $this->stringField($entry, 'title'),
            $reason,
        );
    }

    /**
     * @param array<array-key, mixed> $entry
     */
    private function stringField(array $entry, string $key): string
    {
        $value = $entry[$key] ?? null;

        return \is_string($value) ? $value : '';
    }

    /**
     * @param array<array-key, mixed> $entry
     */
    private function intField(array $entry, string $key): int
    {
        $value = $entry[$key] ?? null;

        return \is_int($value) ? $value : 0;
    }

    /**
     * Trusts the configured `cache.dir` (this memory's parent) and every
     * directory above it, on read and on write.
     */
    private function isSymlinkedPath(string $path): bool
    {
        return SymlinkGuard::isThroughSymlink($path, \dirname($this->directory));
    }
}
