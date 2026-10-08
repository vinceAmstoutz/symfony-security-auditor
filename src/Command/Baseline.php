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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use JsonException;
use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemTriageMemoryStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\BaselineWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

use function Symfony\Component\String\u;

/**
 * Reads and writes the JSON baseline file of accepted-finding fingerprints.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class Baseline implements BaselineInterface
{
    private const int MAX_FEEDBACK_TYPE_LENGTH = 64;

    private const int MAX_FEEDBACK_FILE_LENGTH = 512;

    private const int MAX_FEEDBACK_TITLE_LENGTH = 300;

    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @throws MalformedBaselineFileException
     */
    #[Override]
    public function load(string $path): array
    {
        $fingerprints = [];
        foreach ($this->entries($path) as $baselineEntry) {
            foreach ($baselineEntry->fingerprints() as $fingerprint) {
                $fingerprints[] = $fingerprint;
            }
        }

        return $fingerprints;
    }

    /**
     * @throws MalformedBaselineFileException
     */
    #[Override]
    public function entries(string $path): array
    {
        $entries = [];
        foreach ($this->decodeEntries($path) as $entry) {
            $fingerprint = $this->fingerprintOf($entry, $path);
            $entries[] = new BaselineEntry(
                $fingerprint,
                $this->attackerFingerprintOf($entry),
                \is_array($entry) ? $entry : $fingerprint,
            );
        }

        return $entries;
    }

    /**
     * @throws MalformedBaselineFileException
     */
    #[Override]
    public function feedback(string $path): ReviewerFeedback
    {
        $entries = [];
        foreach ($this->decodeEntries($path) as $entry) {
            $feedbackEntry = $this->feedbackOf($entry);
            if ($feedbackEntry instanceof AcceptedFindingFeedback) {
                $entries[] = $feedbackEntry;
            }
        }

        return new ReviewerFeedback($entries);
    }

    /**
     * @return list<mixed>
     *
     * @throws MalformedBaselineFileException
     */
    private function decodeEntries(string $path): array
    {
        if (!$this->filesystem->exists($path)) {
            return [];
        }

        try {
            $decoded = json_decode($this->filesystem->readFile($path), true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw MalformedBaselineFileException::fromJsonException($path, $jsonException);
        } catch (IOException $ioException) {
            throw MalformedBaselineFileException::fromIOException($path, $ioException);
        }

        if (!\is_array($decoded) || !array_is_list($decoded)) {
            throw MalformedBaselineFileException::notAJsonArrayOfStrings($path);
        }

        return $decoded;
    }

    /**
     * The baseline is part of the audited repository, so a pull request
     * controls every field of an entry, and each one reaches the reviewer's
     * system prompt: each is capped — the reason at the reviewer's own
     * triage-memory cap.
     */
    private function feedbackOf(mixed $entry): ?AcceptedFindingFeedback
    {
        if (!\is_array($entry)) {
            return null;
        }

        $reason = $entry['reason'] ?? null;
        if (!\is_string($reason) || u($reason)->trim()->isEmpty()) {
            return null;
        }

        return new AcceptedFindingFeedback(
            $this->capped($this->stringField($entry, 'type'), self::MAX_FEEDBACK_TYPE_LENGTH),
            $this->capped($this->stringField($entry, 'file'), self::MAX_FEEDBACK_FILE_LENGTH),
            $this->capped($this->stringField($entry, 'title'), self::MAX_FEEDBACK_TITLE_LENGTH),
            $this->capped($reason, FilesystemTriageMemoryStore::MAX_REASON_LENGTH),
        );
    }

    /**
     * Counts code points: a run of combining marks inflates a single grapheme
     * cluster without bound, never a code point count.
     */
    private function capped(string $value, int $maxCodePoints): string
    {
        return mb_substr($value, 0, $maxCodePoints, 'UTF-8');
    }

    /**
     * @param array<array-key, mixed> $entry
     */
    private function stringField(array $entry, string $key): string
    {
        $value = $entry[$key] ?? null;

        return \is_string($value) ? $value : '';
    }

    private function attackerFingerprintOf(mixed $entry): ?string
    {
        if (!\is_array($entry)) {
            return null;
        }

        $attackerFingerprint = $entry['attacker_fingerprint'] ?? null;

        return \is_string($attackerFingerprint) ? $attackerFingerprint : null;
    }

    /**
     * A symlink on the way — below the working directory or below the audited
     * project's root — a path naming a directory, a directory that cannot be
     * created or one the file cannot be written into.
     *
     * @throws UnsafeBaselineWriteException
     * @throws BaselineWriteFailedException
     */
    #[Override]
    public function assertWritable(string $path, string $projectPath): void
    {
        $this->assertSafeToWrite($path, $projectPath);

        if (WritableFilePath::namesADirectory($path)) {
            throw BaselineWriteFailedException::forDirectoryPath($path);
        }

        try {
            $this->filesystem->mkdir(\dirname($path));
        } catch (IOException $ioException) {
            throw BaselineWriteFailedException::forUncreatableDirectory($path, $ioException);
        }

        if (!WritableFilePath::canBeWritten($path)) {
            throw BaselineWriteFailedException::forUnwritablePath($path);
        }
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws UnsafeBaselineWriteException
     */
    #[Override]
    public function save(string $path, array $entries, ?string $projectPath = null): void
    {
        $this->assertSafeToWrite($path, $projectPath);

        try {
            $this->filesystem->dumpFile(
                $path,
                json_encode($entries, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR).\PHP_EOL,
            );
        } catch (JsonException $jsonException) {
            throw MalformedBaselineFileException::fromEncodingException($path, $jsonException);
        } catch (IOException $ioException) {
            throw MalformedBaselineFileException::fromIOException($path, $ioException);
        }
    }

    /**
     * `Filesystem::dumpFile()` transparently writes through a pre-existing
     * symlink at its destination — a predictable, documented baseline path
     * (e.g. `.security-baseline.json`) committed as a symlink by a malicious
     * PR would let the audit overwrite an arbitrary file the CI runner can
     * reach. Mirrors the guard already applied to the filesystem
     * attacker/reviewer/advisory caches, the standalone config writer, and
     * the report writer, and walks the audited project below its root as well.
     *
     * @throws UnsafeBaselineWriteException
     */
    private function assertSafeToWrite(string $path, ?string $projectPath): void
    {
        if (SymlinkGuard::isThroughSymlinkIntoProject($path, $projectPath)) {
            throw UnsafeBaselineWriteException::forSymlinkedPath($path);
        }
    }

    /**
     * @throws MalformedBaselineFileException
     */
    private function fingerprintOf(mixed $entry, string $path): string
    {
        if (\is_string($entry)) {
            return $entry;
        }

        if (\is_array($entry) && \is_string($entry['fingerprint'] ?? null)) {
            return $entry['fingerprint'];
        }

        throw MalformedBaselineFileException::notAJsonArrayOfStrings($path);
    }
}
