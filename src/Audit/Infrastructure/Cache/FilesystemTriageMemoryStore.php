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

use function Symfony\Component\String\u;

/**
 * Filesystem-backed cross-run memory of the reviewer's own rejections: every
 * finding the reviewer rejects with a non-empty `reviewer_notes` is persisted
 * here, keyed by type+file+title, and surfaced back as
 * {@see ReviewerFeedbackProviderInterface} feedback on later runs — so a
 * recurring false positive teaches the reviewer once instead of every run,
 * without a maintainer hand-curating a baseline entry for it.
 *
 * Memory is scoped to the audited project: each project gets its own file
 * under the configured directory, keyed by a hash of its path. A user-global
 * cache directory (the standalone binary's default) is therefore not a
 * cross-project channel — project A's rejections never surface in, or
 * overwrite, project B's feedback.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FilesystemTriageMemoryStore implements ReviewerFeedbackProviderInterface, TriageMemoryRecorderInterface
{
    /**
     * Bounds unbounded growth across months of runs; oldest entries are
     * dropped first.
     */
    public const int DEFAULT_MAX_ENTRIES = 500;

    /**
     * Upper bound on a persisted rejection reason. A reason is
     * reviewer-authored free text replayed into a later run's system prompt;
     * capping it bounds the injected feedback the JSON review path would
     * otherwise persist unbounded.
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
     * Read lazily — never at construction — so the audited project path set on
     * {@see AuditedProjectPathHolder} once the command resolves its argument is
     * the one that scopes the file (mirrors {@see DeferredAdvisoryDatabase}).
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

        // Newest first: entries are appended oldest-to-newest on disk, but the
        // prompt keeps only the first N, so the most recent rejections must lead.
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
            $this->filesystem->dumpFile($path, $encoded);
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

        $entries = [];
        foreach ($decoded as $entry) {
            if (\is_array($entry)) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * Keeps the first-recorded reason for a given finding: a recurring
     * rejection re-recorded on a later cache-miss run leaves the stored reason
     * untouched, so the {@see ReviewerFeedback::digest()} the reviewer cache
     * keys on stops changing and the finding is re-reviewed once after the
     * feedback set grows, then served from cache — instead of the reviewer's
     * freshly-worded notes churning the digest and forcing a full re-review
     * every run.
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
     * The line is part of the key so two distinct findings that share a
     * type/file/title (a generic title reused at different locations) do not
     * collide — the second rejection would otherwise overwrite the first.
     *
     * @param array<array-key, mixed> $entry
     */
    private function keyOf(array $entry): string
    {
        return \sprintf(
            "%s\0%s\0%s\0%d",
            $this->stringField($entry, 'type'),
            $this->stringField($entry, 'file'),
            $this->stringField($entry, 'title'),
            $this->intField($entry, 'line'),
        );
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
     * Mirrors {@see FilesystemReviewerCache}'s symlink guard: this path is
     * config-fixed rather than content-derived, but the same defense — never
     * read or write through a symlink — is cheap to keep as a matter of
     * consistent practice.
     */
    private function isSymlinkedPath(string $path): bool
    {
        return is_link($path) || is_link(\dirname($path));
    }
}
