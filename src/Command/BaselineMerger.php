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
 * are appended.
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
        $findings = $this->reportFindingsLoader->load($reportPath);
        $entries = $this->baseline->entries($baselinePath);

        [$keptEntries, $prunedCount] = $prune ? $this->pruned($entries, $findings) : [$entries, 0];

        return new BaselineMergePlan($keptEntries, $this->notCovered($findings, $keptEntries), $prunedCount);
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
     * @param list<DiffFinding>   $findings
     *
     * @return array{list<BaselineEntry>, int}
     */
    private function pruned(array $entries, array $findings): array
    {
        $remaining = $this->fingerprintCounts($findings);
        $keptEntries = [];
        $prunedCount = 0;

        foreach ($entries as $entry) {
            $coveringFingerprint = $this->coveringFingerprint($remaining, $entry);
            if (null === $coveringFingerprint) {
                ++$prunedCount;

                continue;
            }

            --$remaining[$coveringFingerprint];
            $keptEntries[] = $entry;
        }

        return [$keptEntries, $prunedCount];
    }

    /**
     * @param array<string, int> $remaining
     */
    private function coveringFingerprint(array $remaining, BaselineEntry $baselineEntry): ?string
    {
        foreach ($baselineEntry->fingerprints() as $fingerprint) {
            if (\array_key_exists($fingerprint, $remaining) && $remaining[$fingerprint] > 0) {
                return $fingerprint;
            }
        }

        return null;
    }

    /**
     * @param list<DiffFinding>   $findings
     * @param list<BaselineEntry> $keptEntries
     *
     * @return list<DiffFinding>
     */
    private function notCovered(array $findings, array $keptEntries): array
    {
        $credits = [];
        foreach ($keptEntries as $keptEntry) {
            foreach ($keptEntry->fingerprints() as $fingerprint) {
                $credits[$fingerprint] = ($credits[$fingerprint] ?? 0) + 1;
            }
        }

        $newFindings = [];
        foreach ($findings as $finding) {
            if (\array_key_exists($finding->fingerprint, $credits) && $credits[$finding->fingerprint] > 0) {
                --$credits[$finding->fingerprint];

                continue;
            }

            $newFindings[] = $finding;
        }

        return $newFindings;
    }

    /**
     * @param list<DiffFinding> $findings
     *
     * @return array<string, int>
     */
    private function fingerprintCounts(array $findings): array
    {
        $counts = [];
        foreach ($findings as $finding) {
            $counts[$finding->fingerprint] = ($counts[$finding->fingerprint] ?? 0) + 1;
        }

        return $counts;
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
