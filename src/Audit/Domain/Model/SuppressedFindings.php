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
 * The findings a run found but its report does not list, by fingerprint and
 * one entry per occurrence: the ones the baseline accepted before the reviewer
 * saw them, then the ones taken out of the report afterwards — accepted by the
 * baseline or muted by type.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SuppressedFindings
{
    /**
     * @param list<string> $acceptedBeforeReview baseline credits spent on a finding before the reviewer saw it
     * @param list<string> $removedFromReport
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
        return new self(
            $this->acceptedBeforeReview,
            [
                ...$this->removedFromReport,
                ...array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->fingerprint(), $vulnerabilities),
            ],
        );
    }

    /**
     * @param list<string> $fingerprints
     */
    public function withRemovedFingerprints(array $fingerprints): self
    {
        return new self(
            $this->acceptedBeforeReview,
            [...$this->removedFromReport, ...$fingerprints],
        );
    }

    /**
     * @return list<string>
     */
    public function fingerprints(): array
    {
        return [...$this->acceptedBeforeReview, ...$this->removedFromReport];
    }
}
