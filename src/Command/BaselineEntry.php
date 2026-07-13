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
 * One entry of a baseline file: its accepted fingerprint(s) plus the raw
 * decoded payload, preserved verbatim so merging never loses hand-written
 * keys such as `reason`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BaselineEntry
{
    /**
     * @param array<array-key, mixed>|string $raw
     */
    public function __construct(
        public string $fingerprint,
        public ?string $attackerFingerprint,
        public array|string $raw,
    ) {}

    /**
     * A redundant `attacker_fingerprint` equal to its own `fingerprint` must
     * not grant a count-aware budget of 2 credits for what is really just 1
     * accepted occurrence.
     *
     * @return list<string>
     */
    public function fingerprints(): array
    {
        return null !== $this->attackerFingerprint && $this->attackerFingerprint !== $this->fingerprint
            ? [$this->fingerprint, $this->attackerFingerprint]
            : [$this->fingerprint];
    }
}
