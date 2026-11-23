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
 * One entry of a baseline file, with its raw decoded payload kept verbatim so
 * a merge keeps hand-written keys such as `reason`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
     * The file the entry names, null for a bare fingerprint.
     */
    public function file(): ?string
    {
        $file = \is_array($this->raw) ? $this->raw['file'] ?? null : null;

        return \is_string($file) ? $file : null;
    }

    /**
     * Lists an `attacker_fingerprint` equal to the `fingerprint` once, so the
     * entry still accepts one occurrence.
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
