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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * The findings a run found but its report does not list, one entry per
 * occurrence: the ones the baseline accepted before the reviewer saw them,
 * then the ones taken out of the report afterwards — accepted by the baseline
 * or muted by type. Each is listed under the fingerprint a report gives the
 * finding, beside the baseline fingerprint that left it out.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SuppressedFindings
{
    /**
     * @param list<SuppressedFinding> $acceptedBeforeReview the findings whose baseline credit was spent before the reviewer saw them
     * @param list<SuppressedFinding> $removedFromReport
     */
    public function __construct(
        public array $acceptedBeforeReview = [],
        public array $removedFromReport = [],
    ) {}

    /**
     * @param array<int, Vulnerability> $vulnerabilities
     */
    public function withRemoved(array $vulnerabilities): self
    {
        return $this->withRemovedFindings(array_map(SuppressedFinding::of(...), $vulnerabilities));
    }

    /**
     * @param array<int, SuppressedFinding> $suppressedFindings
     */
    public function withRemovedFindings(array $suppressedFindings): self
    {
        return new self(
            $this->acceptedBeforeReview,
            [...$this->removedFromReport, ...$suppressedFindings],
        );
    }

    /**
     * Names each finding accepted before the review after the baseline entry
     * whose credit it spent: `$entryFingerprintsByBaselineFingerprint` holds,
     * for each baseline fingerprint, the `fingerprint` of every entry carrying
     * it, in the order their credits are named. A finding accepted through an
     * entry's own fingerprint keeps its own, while one accepted through an
     * entry's `attacker_fingerprint` — a finding the reviewer had reclassified —
     * takes the entry's fingerprint, the one a report lists it under.
     *
     * @param array<string, list<string>> $entryFingerprintsByBaselineFingerprint
     */
    public function withAcceptedBeforeReviewNamedBy(array $entryFingerprintsByBaselineFingerprint): self
    {
        $named = [];
        foreach ($this->acceptedBeforeReview as $suppressedFinding) {
            $entryFingerprints = $entryFingerprintsByBaselineFingerprint[$suppressedFinding->baselineFingerprint] ?? [];
            $entryFingerprint = array_shift($entryFingerprints);
            $entryFingerprintsByBaselineFingerprint[$suppressedFinding->baselineFingerprint] = $entryFingerprints;
            $named[] = null === $entryFingerprint || $entryFingerprint === $suppressedFinding->baselineFingerprint ? $suppressedFinding : $suppressedFinding->reportedAs($entryFingerprint);
        }

        return new self($named, $this->removedFromReport);
    }

    /**
     * The fingerprints a report lists these findings under.
     *
     * @return list<string>
     */
    public function fingerprints(): array
    {
        return array_map(
            static fn (SuppressedFinding $suppressedFinding): string => $suppressedFinding->fingerprint,
            [...$this->acceptedBeforeReview, ...$this->removedFromReport],
        );
    }

    /**
     * The baseline fingerprints that left these findings out, in the same
     * order as {@see self::fingerprints()}.
     *
     * @return list<string>
     */
    public function baselineFingerprints(): array
    {
        return $this->baselineFingerprintsOf([...$this->acceptedBeforeReview, ...$this->removedFromReport]);
    }

    /**
     * @return list<string>
     */
    public function baselineFingerprintsAcceptedBeforeReview(): array
    {
        return $this->baselineFingerprintsOf($this->acceptedBeforeReview);
    }

    /**
     * @param list<SuppressedFinding> $suppressedFindings
     *
     * @return list<string>
     */
    private function baselineFingerprintsOf(array $suppressedFindings): array
    {
        return array_map(
            static fn (SuppressedFinding $suppressedFinding): string => $suppressedFinding->baselineFingerprint,
            $suppressedFindings,
        );
    }
}
