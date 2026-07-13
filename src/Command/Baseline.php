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
        foreach ($this->decodeEntries($path) as $entry) {
            foreach ($this->fingerprintsOf($entry, $path) as $fingerprint) {
                $fingerprints[] = $fingerprint;
            }
        }

        return $fingerprints;
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
     * A redundant `attacker_fingerprint` equal to its own `fingerprint` (a
     * hand-edited or merged baseline file could carry one, though the tool's
     * own writer never produces this — `BaselineProcessor::entryFor()` only
     * sets it when the two differ) must not grant a count-aware budget of 2
     * credits for what is really just 1 accepted occurrence.
     *
     * @return list<string>
     *
     * @throws MalformedBaselineFileException
     */
    private function fingerprintsOf(mixed $entry, string $path): array
    {
        $fingerprint = $this->fingerprintOf($entry, $path);
        $attackerFingerprint = $this->attackerFingerprintOf($entry);

        return null !== $attackerFingerprint && $attackerFingerprint !== $fingerprint
            ? [$fingerprint, $attackerFingerprint]
            : [$fingerprint];
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
     * @throws MalformedBaselineFileException
     * @throws UnsafeBaselineWriteException
     */
    #[Override]
    public function save(string $path, array $entries): void
    {
        $this->assertSafeToWrite($path);

        try {
            $this->filesystem->dumpFile(
                $path,
                json_encode($entries, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR).\PHP_EOL,
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
     * the report writer.
     *
     * @throws UnsafeBaselineWriteException
     */
    private function assertSafeToWrite(string $path): void
    {
        if (is_link($path) || is_link(\dirname($path))) {
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
