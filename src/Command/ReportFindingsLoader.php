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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AnalyzedFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\UnanalyzedFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;

/**
 * Loads the findings of a JSON audit report. A finding without a `fingerprint`
 * gets the one {@see Vulnerability::fingerprintOf()} computes from its `type`,
 * `file` and `title`. The `coverage` ledger is read as {@see UnanalyzedFiles}
 * and {@see AnalyzedFiles} read it for a run.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReportFindingsLoader implements ReportFindingsLoaderInterface
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    #[Override]
    public function load(string $path): LoadedReport
    {
        $decoded = $this->decodeReport($path);

        $findings = [];
        $index = 0;
        foreach ($this->vulnerabilitiesIn($decoded, $path) as $vulnerability) {
            if (!\is_array($vulnerability)) {
                throw MalformedReportFileException::vulnerabilityEntryNotAnObject($path, $index);
            }

            $findings[] = $this->toDiffFinding($vulnerability, $path, $index);
            ++$index;
        }

        $coverage = $this->coverageIn($decoded);

        return new LoadedReport(
            $findings,
            new SuppressedFingerprintLists(
                $this->stringsIn($decoded['suppressed_fingerprints'] ?? null),
                $this->stringsIn($decoded['suppressed_baseline_fingerprints'] ?? $decoded['suppressed_fingerprints'] ?? null),
            ),
            $coverage,
            $this->completeRunScanPathsIn($decoded, AnalyzedFiles::in($coverage ?? [])),
            $this->projectPathIn($decoded),
        );
    }

    /**
     * The strings of a `suppressed_fingerprints` or
     * `suppressed_baseline_fingerprints` list, none when it is not a list.
     *
     * @return list<string>
     */
    private function stringsIn(mixed $fingerprints): array
    {
        return \is_array($fingerprints) ? array_values(array_filter($fingerprints, \is_string(...))) : [];
    }

    /**
     * The folder the run audited, null for a report without
     * `suppressed_fingerprints`, whose findings keep the paths the model
     * echoed.
     *
     * @param array<array-key, mixed> $decoded
     */
    private function projectPathIn(array $decoded): ?string
    {
        if (!\array_key_exists('suppressed_fingerprints', $decoded)) {
            return null;
        }

        $project = $decoded['project'] ?? null;

        return \is_string($project) ? $project : '';
    }

    /**
     * The `--path` scopes of a complete run that analyzed a file and recorded
     * a `scope` without `--since`, else null.
     *
     * @param array<array-key, mixed> $decoded
     * @param list<string>            $analyzedFiles
     *
     * @return list<string>|null
     */
    private function completeRunScanPathsIn(array $decoded, array $analyzedFiles): ?array
    {
        $scope = $decoded['scope'] ?? null;
        if (true !== ($decoded['complete'] ?? null) || [] === $analyzedFiles || !\is_array($scope) || !\array_key_exists('since', $scope) || null !== $scope['since'] || !\is_array($scope['paths'] ?? null)) {
            return null;
        }

        return array_values(array_filter($scope['paths'], \is_string(...)));
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    private function decodeReport(string $path): array
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

        return $decoded;
    }

    /**
     * @param array<array-key, mixed> $decoded
     *
     * @return array<array-key, mixed>
     *
     * @throws MalformedReportFileException
     */
    private function vulnerabilitiesIn(array $decoded, string $path): array
    {
        $vulnerabilities = $decoded['vulnerabilities'] ?? null;
        if (!\is_array($vulnerabilities)) {
            throw MalformedReportFileException::missingVulnerabilitiesArray($path);
        }

        return $vulnerabilities;
    }

    /**
     * The coverage ledger, null when the report has none. A malformed entry is
     * left out.
     *
     * @param array<array-key, mixed> $decoded
     *
     * @return list<array{stage: string, file: string, status: string}>|null
     */
    private function coverageIn(array $decoded): ?array
    {
        $coverage = $decoded['coverage'] ?? null;
        if (!\is_array($coverage)) {
            return null;
        }

        $entries = [];
        foreach ($coverage as $entry) {
            if (\is_array($entry) && \is_string($entry['stage'] ?? null) && \is_string($entry['file'] ?? null) && \is_string($entry['status'] ?? null)) {
                $entries[] = ['stage' => $entry['stage'], 'file' => $entry['file'], 'status' => $entry['status']];
            }
        }

        return $entries;
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
