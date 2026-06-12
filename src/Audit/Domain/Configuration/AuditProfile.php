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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

/**
 * One-knob preset bundling the cost/speed/depth levers. A profile only fills
 * the keys the user left unset — any explicitly configured key always wins.
 *
 * - `fast` — cheapest and quickest: a single attacker iteration over
 *   marker-bearing files only (lean pre-scan), large files sliced to their
 *   security-relevant lines, and up to four concurrent reviewer calls.
 * - `balanced` — the default; identical to configuring nothing.
 * - `thorough` — adds PoC synthesis for high-severity validated findings on
 *   top of the balanced depth.
 */
enum AuditProfile: string
{
    case Fast = 'fast';
    case Balanced = 'balanced';
    case Thorough = 'thorough';

    public function maxIterations(): int
    {
        return match ($this) {
            self::Fast => 1,
            self::Balanced, self::Thorough => 3,
        };
    }

    public function staticPreScanLeanMode(): bool
    {
        return self::Fast === $this;
    }

    public function codeSlicingEnabled(): bool
    {
        return self::Fast === $this;
    }

    public function poCSynthesisEnabled(): bool
    {
        return self::Thorough === $this;
    }

    public function reviewerMaxConcurrent(): int
    {
        return match ($this) {
            self::Fast => 4,
            self::Balanced, self::Thorough => 1,
        };
    }
}
