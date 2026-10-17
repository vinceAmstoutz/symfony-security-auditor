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
 * The baseline entries that hold a finding under one of its former names
 * ({@see FormerFindingNames}), looked up by name instead of by matching the
 * finding against every entry. Of the entries sharing a fingerprint, only the
 * first one is kept: a finding spends a fingerprint's credit, not one entry.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class HoldingEntries
{
    /**
     * @param list<string>                      $fingerprints         the fingerprint of each entry, in baseline order
     * @param array<string, int>                $byFingerprint        the position of the first entry of each fingerprint
     * @param array<string, array<string, int>> $byFileAndFingerprint the same among the entries naming each file
     */
    private function __construct(
        private array $fingerprints,
        private array $byFingerprint,
        private array $byFileAndFingerprint,
    ) {}

    /**
     * @param list<BaselineEntry> $baselineEntries
     */
    public static function of(array $baselineEntries): self
    {
        $byFingerprint = [];
        $byFileAndFingerprint = [];
        foreach ($baselineEntries as $position => $baselineEntry) {
            $byFingerprint[$baselineEntry->fingerprint] ??= $position;
            $file = $baselineEntry->file();
            if (null !== $file) {
                $byFileAndFingerprint[$file][$baselineEntry->fingerprint] ??= $position;
            }
        }

        return new self(
            array_map(static fn (BaselineEntry $baselineEntry): string => $baselineEntry->fingerprint, $baselineEntries),
            $byFingerprint,
            $byFileAndFingerprint,
        );
    }

    /**
     * The fingerprints of the entries holding a finding under one of `$names`,
     * in the order the baseline lists them.
     *
     * @param list<array{string|null, string}> $names
     *
     * @return list<string>
     */
    public function holding(array $names): array
    {
        $positions = [];
        foreach ($names as [$entryFile, $name]) {
            $position = null === $entryFile ? $this->byFingerprint[$name] ?? null : $this->byFileAndFingerprint[$entryFile][$name] ?? null;
            if (null !== $position) {
                $positions[] = $position;
            }
        }

        sort($positions);

        return array_map(fn (int $position): string => $this->fingerprints[$position], $positions);
    }
}
