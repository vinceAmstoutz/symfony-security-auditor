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
 * @internal not part of the BC promise — see docs/versioning.md
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

        [$fixed, $unverified] = $this->partitionByAnalysis($this->only($previousFindings, $currentFindings), $currentReport);

        return new ReportDiff(
            $this->only($currentFindings, $previousFindings),
            $fixed,
            $this->intersect($currentFindings, $previousFindings),
            $unverified,
        );
    }

    /**
     * A finding that disappeared from a file the current run never finished
     * analyzing, or never looked at, is not fixed — nobody looked — so it is
     * kept apart from the ones whose file was analyzed and came back clean.
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
     * Two distinct findings can share a fingerprint (same type/file/title,
     * different line) — grouping by fingerprint instead of overwriting keeps
     * both instead of silently dropping one. Buckets are paired off by count:
     * a fingerprint with more entries in `$findings` than in `$excluded`
     * contributes only its excess as "not excluded", matching each shared
     * entry 1:1 before counting anything as new/fixed.
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
