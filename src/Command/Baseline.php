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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\BoundedFileReader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\UnreadableInputFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\BaselineWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

use function Symfony\Component\String\b;
use function Symfony\Component\String\u;

/**
 * Reads and writes the JSON baseline file of accepted-finding fingerprints.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class Baseline implements BaselineInterface
{
    private const int MAX_FEEDBACK_TYPE_LENGTH = 64;

    private const int MAX_FEEDBACK_FILE_LENGTH = 512;

    private const int MAX_FEEDBACK_TITLE_LENGTH = 300;

    private const string INVISIBLE_FORMAT_CHARACTERS = '/[\x{061C}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{206F}\x{FEFF}\x{E0000}-\x{E007F}]/u';

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
            $decoded = json_decode(BoundedFileReader::read($path), true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw MalformedBaselineFileException::fromJsonException($path, $jsonException);
        } catch (UnreadableInputFileException $unreadableInputFileException) {
            throw MalformedBaselineFileException::fromIOException($path, $unreadableInputFileException);
        }

        if (!\is_array($decoded) || !array_is_list($decoded)) {
            throw MalformedBaselineFileException::notAJsonArrayOfStrings($path);
        }

        return $decoded;
    }

    /**
     * Caps every field: a pull request controls the baseline and each field
     * reaches the reviewer's system prompt.
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
     * Caps code points, not grapheme clusters, which combining marks inflate
     * without bound.
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
     * Refuses a symlink below the working directory or the project root, a
     * path naming a directory and a directory that cannot be created or
     * written into.
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
            WritableFilePath::dump($this->filesystem, $path, $this->encode($entries).\PHP_EOL);
        } catch (JsonException $jsonException) {
            throw MalformedBaselineFileException::fromEncodingException($path, $jsonException);
        } catch (IOException $ioException) {
            throw MalformedBaselineFileException::fromIOException($path, $ioException);
        }
    }

    /**
     * @param list<array<array-key, mixed>|string> $entries
     *
     * @throws JsonException
     */
    private function encode(array $entries): string
    {
        return b(json_encode($entries, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR))
            ->replaceMatches(self::INVISIBLE_FORMAT_CHARACTERS, static fn (array $match): string => substr(json_encode($match[0], \JSON_THROW_ON_ERROR), 1, -1))
            ->toString();
    }

    /**
     * Refuses a path through a symlink below the working directory or the
     * project root, which `dumpFile()` would follow to any file the runner can
     * reach.
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
