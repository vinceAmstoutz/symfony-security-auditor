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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;

/**
 * Loads the findings of a JSON audit report. A report generated before the
 * `fingerprint` key existed is still accepted: its fingerprint is recomputed
 * from `type`, `file`, and `title` with the exact formula
 * {@see Vulnerability::fingerprintOf()} uses, so it never drifts from the
 * canonical identity.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReportFindingsLoader implements ReportFindingsLoaderInterface
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    #[Override]
    public function load(string $path): array
    {
        $findings = [];
        $index = 0;
        foreach ($this->decodeVulnerabilities($path) as $vulnerability) {
            if (!\is_array($vulnerability)) {
                throw MalformedReportFileException::vulnerabilityEntryNotAnObject($path, $index);
            }

            $findings[] = $this->toDiffFinding($vulnerability, $path, $index);
            ++$index;
        }

        return $findings;
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    private function decodeVulnerabilities(string $path): array
    {
        if (!$this->filesystem->exists($path)) {
            throw ReportFileNotReadableException::forPath($path);
        }

        try {
            $content = $this->filesystem->readFile($path);
        } catch (IOException $ioException) {
            throw ReportFileNotReadableException::forPath($path, $ioException);
        }

        try {
            $decoded = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw MalformedReportFileException::fromJsonException($path, $jsonException);
        }

        if (!\is_array($decoded)) {
            throw MalformedReportFileException::missingVulnerabilitiesArray($path);
        }

        $vulnerabilities = $decoded['vulnerabilities'] ?? null;
        if (!\is_array($vulnerabilities)) {
            throw MalformedReportFileException::missingVulnerabilitiesArray($path);
        }

        return $vulnerabilities;
    }

    /**
     * @param array<array-key, mixed> $vulnerability
     *
     * @throws MalformedReportFileException
     */
    private function toDiffFinding(array $vulnerability, string $path, int $index): DiffFinding
    {
        $type = $vulnerability['type'] ?? null;
        $file = $vulnerability['file'] ?? null;
        $title = $vulnerability['title'] ?? null;
        $severity = $vulnerability['severity'] ?? null;

        if (!\is_string($type) || !\is_string($file) || !\is_string($title) || !\is_string($severity)) {
            throw MalformedReportFileException::invalidVulnerabilityEntry($path, $index);
        }

        $fingerprint = $vulnerability['fingerprint'] ?? null;

        return new DiffFinding(
            \is_string($fingerprint) ? $fingerprint : Vulnerability::fingerprintOf($type, $file, $title),
            $type,
            $file,
            $title,
            $severity,
        );
    }
}
