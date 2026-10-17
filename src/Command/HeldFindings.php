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

/**
 * The findings of a report each baseline entry holds under a former name
 * ({@see FormerFindingNames}), looked up by the entry's fingerprint — and its
 * file, for a name only an entry naming that file holds — instead of by
 * matching the entry against every finding. Of the findings sharing a
 * fingerprint, only the first one held under each name is kept: a prune spends
 * a fingerprint, not one of its occurrences.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class HeldFindings
{
    /**
     * @param list<string>                                     $fingerprints         the fingerprint of each finding, in report order
     * @param array<string, array<string, int>>                $byFingerprint        under each name any entry holds a finding by: the position of the first finding of each fingerprint held so
     * @param array<string, array<string, array<string, int>>> $byFileAndFingerprint the same for the names only an entry naming that file holds a finding by
     */
    private function __construct(
        private array $fingerprints,
        private array $byFingerprint,
        private array $byFileAndFingerprint,
    ) {}

    public static function of(LoadedReport $loadedReport, FormerFindingNames $formerFindingNames): self
    {
        $byFingerprint = [];
        $byFileAndFingerprint = [];
        foreach ($loadedReport->findings as $position => $diffFinding) {
            foreach ($formerFindingNames->of($diffFinding) as [$entryFile, $name]) {
                if (null === $entryFile) {
                    $byFingerprint[$name][$diffFinding->fingerprint] ??= $position;

                    continue;
                }

                $byFileAndFingerprint[$entryFile][$name][$diffFinding->fingerprint] ??= $position;
            }
        }

        return new self(
            array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->fingerprint, $loadedReport->findings),
            $byFingerprint,
            $byFileAndFingerprint,
        );
    }

    /**
     * The fingerprints of the findings `$baselineEntry` holds under a former
     * name, in the order the report lists them.
     *
     * @return list<string>
     */
    public function heldBy(BaselineEntry $baselineEntry): array
    {
        $positions = [];
        foreach ($this->firstPositionsHeldBy($baselineEntry) as $firstPositions) {
            foreach ($firstPositions as $firstPosition) {
                $positions[] = $firstPosition;
            }
        }

        sort($positions);

        return array_map(fn (int $position): string => $this->fingerprints[$position], $positions);
    }

    /**
     * @return array{array<string, int>, array<string, int>} under the entry's fingerprint, then under its file and fingerprint
     */
    private function firstPositionsHeldBy(BaselineEntry $baselineEntry): array
    {
        $file = $baselineEntry->file();

        return [
            $this->byFingerprint[$baselineEntry->fingerprint] ?? [],
            null === $file ? [] : $this->byFileAndFingerprint[$file][$baselineEntry->fingerprint] ?? [],
        ];
    }
}
