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
 * One-knob preset. It fills only the keys left unset: an explicit key wins.
 *
 * - `fast`: one attacker iteration over marker-bearing files only, large files
 *   sliced and up to four concurrent attacker and reviewer calls.
 * - `balanced`: the default, identical to configuring nothing.
 * - `thorough`: `balanced` plus PoC synthesis for high-severity validated
 *   findings and `since_closure: direct`.
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

    public function attackerMaxConcurrent(): int
    {
        return match ($this) {
            self::Fast => 4,
            self::Balanced, self::Thorough => 1,
        };
    }

    public function sinceClosure(): string
    {
        return self::Thorough === $this ? 'direct' : 'none';
    }
}
