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
        $previousFindings = $this->indexByFingerprint($this->reportFindingsLoader->load($previousReportPath));
        $currentFindings = $this->indexByFingerprint($this->reportFindingsLoader->load($currentReportPath));

        return new ReportDiff(
            $this->only($currentFindings, $previousFindings),
            $this->only($previousFindings, $currentFindings),
            $this->intersect($currentFindings, $previousFindings),
        );
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
            $result = [...$result, ...\array_slice($group, \count($excluded[$fingerprint] ?? []))];
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
            $result = [...$result, ...\array_slice($group, 0, \count($other[$fingerprint] ?? []))];
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
