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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;

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
        if (!$this->filesystem->exists($path)) {
            return [];
        }

        try {
            $decoded = json_decode($this->filesystem->readFile($path), true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw MalformedBaselineFileException::fromJsonException($path, $jsonException);
        }

        if (!\is_array($decoded)) {
            throw MalformedBaselineFileException::notAJsonArrayOfStrings($path);
        }

        $fingerprints = [];
        foreach ($decoded as $entry) {
            $fingerprints[] = $this->fingerprintOf($entry, $path);
            $attackerFingerprint = $this->attackerFingerprintOf($entry);
            if (null !== $attackerFingerprint) {
                $fingerprints[] = $attackerFingerprint;
            }
        }

        return $fingerprints;
    }

    private function attackerFingerprintOf(mixed $entry): ?string
    {
        if (!\is_array($entry)) {
            return null;
        }

        $attackerFingerprint = $entry['attacker_fingerprint'] ?? null;

        return \is_string($attackerFingerprint) ? $attackerFingerprint : null;
    }

    #[Override]
    public function save(string $path, array $entries): void
    {
        $this->filesystem->dumpFile(
            $path,
            json_encode($entries, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR).\PHP_EOL,
        );
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
