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
 * One occurrence of a finding a run found and its report leaves out: the
 * fingerprint a report lists the finding under, and the one that left it out
 * — the baseline fingerprint whose credit it spent, which a baseline may hold
 * under another type or path spelling than the finding's own, or its own
 * fingerprint when its type is muted.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SuppressedFinding
{
    public function __construct(
        public string $fingerprint,
        public string $baselineFingerprint,
    ) {}

    public static function of(Vulnerability $vulnerability): self
    {
        return new self($vulnerability->fingerprint(), $vulnerability->fingerprint());
    }

    public function reportedAs(string $fingerprint): self
    {
        return new self($fingerprint, $this->baselineFingerprint);
    }
}
