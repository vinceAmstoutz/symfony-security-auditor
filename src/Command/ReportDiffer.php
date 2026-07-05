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
 * Compares two decoded JSON audit reports by finding fingerprint. A report
 * generated before the `fingerprint` key existed is still accepted: its
 * fingerprint is recomputed from `type`, `file`, and `title` with the exact
 * formula {@see Vulnerability::fingerprintOf()} uses, so it never drifts from
 * the canonical identity.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReportDiffer implements ReportDifferInterface
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    #[Override]
    public function diff(string $previousReportPath, string $currentReportPath): ReportDiff
    {
        $previousFindings = $this->indexByFingerprint($this->loadFindings($previousReportPath));
        $currentFindings = $this->indexByFingerprint($this->loadFindings($currentReportPath));

        return new ReportDiff(
            $this->only($currentFindings, $previousFindings),
            $this->only($previousFindings, $currentFindings),
            $this->intersect($currentFindings, $previousFindings),
        );
    }

    /**
     * @return list<DiffFinding>
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    private function loadFindings(string $path): array
    {
        $findings = [];
        foreach ($this->decodeVulnerabilities($path) as $index => $vulnerability) {
            if (!\is_array($vulnerability)) {
                throw MalformedReportFileException::invalidVulnerabilityEntry($path, (int) $index);
            }

            $findings[] = $this->toDiffFinding($vulnerability, $path, (int) $index);
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

    /**
     * @param array<string, DiffFinding> $findings
     * @param array<string, DiffFinding> $excluded
     *
     * @return list<DiffFinding>
     */
    private function only(array $findings, array $excluded): array
    {
        return array_values(array_filter(
            $findings,
            static fn (DiffFinding $diffFinding): bool => !\array_key_exists($diffFinding->fingerprint, $excluded),
        ));
    }

    /**
     * @param array<string, DiffFinding> $findings
     * @param array<string, DiffFinding> $other
     *
     * @return list<DiffFinding>
     */
    private function intersect(array $findings, array $other): array
    {
        return array_values(array_filter(
            $findings,
            static fn (DiffFinding $diffFinding): bool => \array_key_exists($diffFinding->fingerprint, $other),
        ));
    }

    /**
     * @param list<DiffFinding> $findings
     *
     * @return array<string, DiffFinding>
     */
    private function indexByFingerprint(array $findings): array
    {
        $indexed = [];
        foreach ($findings as $finding) {
            $indexed[$finding->fingerprint] = $finding;
        }

        return $indexed;
    }
}
