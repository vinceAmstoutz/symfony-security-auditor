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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineEntry;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffFinding;
use VinceAmstoutz\SymfonySecurityAuditor\Command\LoadedReport;

/**
 * The merge `audit:baseline` performed when it matched every baseline entry
 * against every finding of the report, kept as the specification the indexed
 * merge must reproduce result for result.
 */
final readonly class PairwiseBaselineMerge
{
    /**
     * @param list<BaselineEntry> $entries
     *
     * @return array{list<BaselineEntry>, list<DiffFinding>, int}
     */
    public static function plan(LoadedReport $loadedReport, array $entries, bool $prune): array
    {
        [$keptEntries, $prunedCount] = $prune ? self::pruned($entries, $loadedReport) : [$entries, 0];

        return [$keptEntries, self::notCovered($loadedReport, $keptEntries), $prunedCount];
    }

    /**
     * @param list<BaselineEntry> $entries
     *
     * @return array{list<BaselineEntry>, int}
     */
    private static function pruned(array $entries, LoadedReport $loadedReport): array
    {
        $remaining = array_count_values([
            ...array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->fingerprint, $loadedReport->findings),
            ...$loadedReport->suppressedBaselineFingerprints,
        ]);
        $keptEntries = [];
        $prunedCount = 0;

        foreach ($entries as $entry) {
            $coveringFingerprint = self::coveringFingerprint($remaining, $entry, $loadedReport);
            if (null !== $coveringFingerprint) {
                --$remaining[$coveringFingerprint];
            }

            $file = $entry->file();
            if (null === $coveringFingerprint && (null === $file || $loadedReport->vouchesForAbsenceIn($file))) {
                ++$prunedCount;

                continue;
            }

            $keptEntries[] = $entry;
        }

        return [$keptEntries, $prunedCount];
    }

    /**
     * @param array<string, int> $remaining
     */
    private static function coveringFingerprint(array $remaining, BaselineEntry $baselineEntry, LoadedReport $loadedReport): ?string
    {
        $ownFingerprint = self::firstWithCredit($remaining, $baselineEntry->fingerprints());
        if (null !== $ownFingerprint) {
            return $ownFingerprint;
        }

        foreach ($loadedReport->findings as $diffFinding) {
            if ($remaining[$diffFinding->fingerprint] > 0 && self::holds($baselineEntry, $diffFinding, $loadedReport)) {
                return $diffFinding->fingerprint;
            }
        }

        return null;
    }

    /**
     * @param array<string, int> $remaining
     * @param list<string>       $fingerprints
     */
    private static function firstWithCredit(array $remaining, array $fingerprints): ?string
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
    private static function notCovered(LoadedReport $loadedReport, array $keptEntries): array
    {
        $credits = [];
        foreach ($keptEntries as $keptEntry) {
            foreach ($keptEntry->fingerprints() as $fingerprint) {
                $credits[$fingerprint] = ($credits[$fingerprint] ?? 0) + 1;
            }
        }

        $newFindings = [];
        foreach ($loadedReport->findings as $finding) {
            $credit = self::creditCovering($credits, $finding, $keptEntries, $loadedReport);
            if (null !== $credit) {
                --$credits[$credit];

                continue;
            }

            $newFindings[] = $finding;
        }

        return $newFindings;
    }

    /**
     * @param array<string, int>  $credits
     * @param list<BaselineEntry> $keptEntries
     */
    private static function creditCovering(array $credits, DiffFinding $diffFinding, array $keptEntries, LoadedReport $loadedReport): ?string
    {
        $ownFingerprint = self::firstWithCredit($credits, [$diffFinding->fingerprint]);
        if (null !== $ownFingerprint) {
            return $ownFingerprint;
        }

        foreach ($keptEntries as $keptEntry) {
            if ($credits[$keptEntry->fingerprint] > 0 && self::holds($keptEntry, $diffFinding, $loadedReport)) {
                return $keptEntry->fingerprint;
            }
        }

        return null;
    }

    private static function holds(BaselineEntry $baselineEntry, DiffFinding $diffFinding, LoadedReport $loadedReport): bool
    {
        return null !== $loadedReport->projectPath
            && \in_array($baselineEntry->fingerprint, self::formerFingerprintsOf($diffFinding, $baselineEntry->file(), $loadedReport->projectPath), true);
    }

    /**
     * @return list<string>
     */
    private static function formerFingerprintsOf(DiffFinding $diffFinding, ?string $entryFile, string $projectPath): array
    {
        $spellings = [
            $diffFinding->file,
            ...(null !== $entryFile && self::denotes($entryFile, $diffFinding->file, $projectPath) ? [$entryFile] : []),
        ];
        $types = [
            $diffFinding->type,
            ...array_map(
                static fn (VulnerabilityType $vulnerabilityType): string => $vulnerabilityType->value,
                VulnerabilityType::tryFrom($diffFinding->type)?->formerTypes() ?? [],
            ),
        ];

        $fingerprints = [];
        foreach ($spellings as $spelling) {
            foreach ($types as $type) {
                $fingerprints[] = Vulnerability::fingerprintOf($type, $spelling, $diffFinding->title);
            }
        }

        return $fingerprints;
    }

    private static function denotes(string $entryFile, string $file, string $projectPath): bool
    {
        $echoed = EchoedFilePath::comparable($entryFile);

        return EchoedFilePath::comparable($file) === $echoed || EchoedFilePath::comparable(\sprintf('%s/%s', $projectPath, $file)) === $echoed;
    }
}
