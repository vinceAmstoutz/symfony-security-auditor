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
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\Clock;

/**
 * Merges a JSON report's findings into a baseline file without re-running
 * the audit: existing entries are preserved verbatim — hand-written keys
 * such as `reason` survive — and only findings not yet covered by an entry
 * are appended. A prune drops only the entries whose finding the report
 * shows gone: an entry whose file the report did not analyze is kept, the
 * way `audit:diff` keeps such a finding apart as unverified. An entry a
 * baseline written before 1.22 holds under a former name of the finding
 * ({@see FormerFindingNames}) covers it as its own fingerprint would; those
 * names are computed once per finding and looked up by fingerprint, so a merge
 * grows with the size of the report and of the baseline, not their product.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BaselineMerger implements BaselineMergerInterface
{
    public function __construct(
        private ReportFindingsLoaderInterface $reportFindingsLoader,
        private BaselineInterface $baseline,
        private ClockInterface $clock = new Clock(),
    ) {}

    #[Override]
    public function plan(string $reportPath, string $baselinePath, bool $prune): BaselineMergePlan
    {
        $loadedReport = $this->reportFindingsLoader->load($reportPath);
        $entries = $this->baseline->entries($baselinePath);

        [$keptEntries, $prunedCount] = $prune ? $this->pruned($entries, $loadedReport) : [$entries, 0];

        return new BaselineMergePlan($keptEntries, $this->notCovered($loadedReport, $keptEntries), $prunedCount);
    }

    #[Override]
    public function commit(string $baselinePath, BaselineMergePlan $baselineMergePlan, array $reasons): void
    {
        $entries = array_map(
            static fn (BaselineEntry $baselineEntry): array|string => $baselineEntry->raw,
            $baselineMergePlan->keptEntries,
        );

        foreach ($baselineMergePlan->newFindings as $index => $newFinding) {
            $entries[] = $this->entryFor($newFinding, $reasons[$index] ?? null);
        }

        $this->baseline->save($baselinePath, $entries);
    }

    /**
     * @param list<BaselineEntry> $entries
     *
     * @return array{list<BaselineEntry>, int}
     */
    private function pruned(array $entries, LoadedReport $loadedReport): array
    {
        $remaining = $this->fingerprintCounts($loadedReport);
        $heldFindings = HeldFindings::of($loadedReport, FormerFindingNames::in($loadedReport, $entries));
        $keptEntries = [];
        $prunedCount = 0;

        foreach ($entries as $entry) {
            $coveringFingerprint = $this->coveringFingerprint($remaining, $entry, $heldFindings);
            if (null !== $coveringFingerprint) {
                --$remaining[$coveringFingerprint];
            }

            if (null === $coveringFingerprint && $this->reportVouchesForItsAbsence($entry, $loadedReport)) {
                ++$prunedCount;

                continue;
            }

            $keptEntries[] = $entry;
        }

        return [$keptEntries, $prunedCount];
    }

    /**
     * An entry that names no file cannot be placed, so the report is trusted
     * as it always was.
     */
    private function reportVouchesForItsAbsence(BaselineEntry $baselineEntry, LoadedReport $loadedReport): bool
    {
        $file = $baselineEntry->file();

        return null === $file || $loadedReport->vouchesForAbsenceIn($file);
    }

    /**
     * One of the entry's own fingerprints the report still lists, else the
     * fingerprint of the first listed finding the entry holds under a former
     * name.
     *
     * @param array<string, int> $remaining
     */
    private function coveringFingerprint(array $remaining, BaselineEntry $baselineEntry, HeldFindings $heldFindings): ?string
    {
        return $this->firstWithCredit($remaining, [...$baselineEntry->fingerprints(), ...$heldFindings->heldBy($baselineEntry)]);
    }

    /**
     * @param array<string, int> $remaining
     * @param list<string>       $fingerprints
     */
    private function firstWithCredit(array $remaining, array $fingerprints): ?string
    {
        foreach ($fingerprints as $fingerprint) {
            if (\array_key_exists($fingerprint, $remaining) && $remaining[$fingerprint] > 0) {
                return $fingerprint;
            }
        }

        return null;
    }

    /**
     * @param list<BaselineEntry> $keptEntries
     *
     * @return list<DiffFinding>
     */
    private function notCovered(LoadedReport $loadedReport, array $keptEntries): array
    {
        $credits = [];
        foreach ($keptEntries as $keptEntry) {
            foreach ($keptEntry->fingerprints() as $fingerprint) {
                $credits[$fingerprint] = ($credits[$fingerprint] ?? 0) + 1;
            }
        }

        $formerFindingNames = FormerFindingNames::in($loadedReport, $keptEntries);
        $holdingEntries = HoldingEntries::of($keptEntries);
        $newFindings = [];
        foreach ($loadedReport->findings as $finding) {
            $credit = $this->creditCovering($credits, $finding, $holdingEntries->holding($formerFindingNames->of($finding)));
            if (null !== $credit) {
                --$credits[$credit];

                continue;
            }

            $newFindings[] = $finding;
        }

        return $newFindings;
    }

    /**
     * The finding's own fingerprint while an entry still accepts it, else the
     * fingerprint of the first kept entry that holds it under a former name:
     * the order `AuditContext::consumeBaselineCreditFor()` spends a baseline
     * in.
     *
     * @param array<string, int> $credits
     * @param list<string>       $holdingFingerprints the fingerprints of the kept entries holding it under a former name, in baseline order
     */
    private function creditCovering(array $credits, DiffFinding $diffFinding, array $holdingFingerprints): ?string
    {
        return $this->firstWithCredit($credits, [$diffFinding->fingerprint, ...$holdingFingerprints]);
    }

    /**
     * Every occurrence the run found, whether its report lists the finding or
     * leaves it out because the baseline accepted it or its type is muted — a
     * finding left out counted under the baseline fingerprint that accepted
     * it, which an entry written under another type or path holds.
     *
     * @return array<string, int>
     */
    private function fingerprintCounts(LoadedReport $loadedReport): array
    {
        return array_count_values([
            ...array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->fingerprint, $loadedReport->findings),
            ...$loadedReport->suppressedBaselineFingerprints,
        ]);
    }

    /**
     * @return array<string, string>
     */
    private function entryFor(DiffFinding $diffFinding, ?string $reason): array
    {
        $entry = [
            'fingerprint' => $diffFinding->fingerprint,
            'type' => $diffFinding->type,
            'file' => $diffFinding->file,
            'title' => $diffFinding->title,
            'added_at' => $this->clock->now()->format('Y-m-d'),
        ];

        if (null !== $reason) {
            $entry['reason'] = $reason;
        }

        return $entry;
    }
}
