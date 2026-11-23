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

use Override;

/**
 * Compares two decoded JSON audit reports by finding fingerprint.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReportDiffer implements ReportDifferInterface
{
    public function __construct(
        private ReportFindingsLoaderInterface $reportFindingsLoader = new ReportFindingsLoader(),
    ) {}

    #[Override]
    public function diff(string $previousReportPath, string $currentReportPath): ReportDiff
    {
        return $this->compare(
            $this->reportFindingsLoader->load($previousReportPath),
            $this->reportFindingsLoader->load($currentReportPath),
        );
    }

    #[Override]
    public function diffSeries(array $reportPaths): array
    {
        $reportDiffs = [];
        $previousReport = null;
        foreach ($reportPaths as $reportPath) {
            $currentReport = $this->reportFindingsLoader->load($reportPath);
            if ($previousReport instanceof LoadedReport) {
                $reportDiffs[] = $this->compare($previousReport, $currentReport);
            }

            $previousReport = $currentReport;
        }

        return $reportDiffs;
    }

    private function compare(LoadedReport $loadedReport, LoadedReport $currentReport): ReportDiff
    {
        $previousFindings = $this->indexByFingerprint($loadedReport->findings);
        $currentFindings = $this->indexByFingerprint($currentReport->findings);

        [$suppressed, $disappeared] = $this->partitionBySuppression($this->only($previousFindings, $currentFindings), $currentReport->suppressedFingerprints);
        [$fixed, $unverified] = $this->partitionByAnalysis($disappeared, $currentReport);

        return new ReportDiff(
            $this->only($currentFindings, $previousFindings),
            $fixed,
            $this->intersect($currentFindings, $previousFindings),
            [...$suppressed, ...$unverified],
        );
    }

    /**
     * Splits off the findings the current report left out as accepted or
     * muted, one per fingerprint it lists as suppressed.
     *
     * @param list<DiffFinding> $disappeared
     * @param list<string>      $suppressedFingerprints
     *
     * @return array{list<DiffFinding>, list<DiffFinding>}
     */
    private function partitionBySuppression(array $disappeared, array $suppressedFingerprints): array
    {
        $credits = array_count_values($suppressedFingerprints);
        $suppressed = [];
        $remaining = [];
        foreach ($disappeared as $finding) {
            if (\array_key_exists($finding->fingerprint, $credits) && $credits[$finding->fingerprint] > 0) {
                --$credits[$finding->fingerprint];
                $suppressed[] = $finding;

                continue;
            }

            $remaining[] = $finding;
        }

        return [$suppressed, $remaining];
    }

    /**
     * Splits the fixed findings from those whose file the current report
     * cannot vouch for.
     *
     * @param list<DiffFinding> $disappeared
     *
     * @return array{list<DiffFinding>, list<DiffFinding>}
     */
    private function partitionByAnalysis(array $disappeared, LoadedReport $loadedReport): array
    {
        $fixed = [];
        $unverified = [];
        foreach ($disappeared as $finding) {
            if ($loadedReport->vouchesForAbsenceIn($finding->file)) {
                $fixed[] = $finding;

                continue;
            }

            $unverified[] = $finding;
        }

        return [$fixed, $unverified];
    }

    /**
     * The findings of each fingerprint beyond its count in `$excluded`, so two
     * findings sharing a fingerprint count twice.
     *
     * @param array<string, list<DiffFinding>> $findings
     * @param array<string, list<DiffFinding>> $excluded
     *
     * @return list<DiffFinding>
     */
    private function only(array $findings, array $excluded): array
    {
        $result = [];
        foreach ($findings as $fingerprint => $group) {
            foreach (\array_slice($group, \count($excluded[$fingerprint] ?? [])) as $finding) {
                $result[] = $finding;
            }
        }

        return $result;
    }

    /**
     * @param array<string, list<DiffFinding>> $findings
     * @param array<string, list<DiffFinding>> $other
     *
     * @return list<DiffFinding>
     */
    private function intersect(array $findings, array $other): array
    {
        $result = [];
        foreach ($findings as $fingerprint => $group) {
            foreach (\array_slice($group, 0, \count($other[$fingerprint] ?? [])) as $finding) {
                $result[] = $finding;
            }
        }

        return $result;
    }

    /**
     * @param list<DiffFinding> $findings
     *
     * @return array<string, list<DiffFinding>>
     */
    private function indexByFingerprint(array $findings): array
    {
        $indexed = [];
        foreach ($findings as $finding) {
            $indexed[$finding->fingerprint][] = $finding;
        }

        return $indexed;
    }
}
