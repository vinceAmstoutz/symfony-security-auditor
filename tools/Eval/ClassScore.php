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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval;

/**
 * Precision / recall / F1 for one vulnerability class (or the aggregate),
 * computed from true-positive, false-positive, and false-negative counts.
 */
final readonly class ClassScore
{
    public function __construct(
        public string $type,
        public int $truePositives,
        public int $falsePositives,
        public int $falseNegatives,
    ) {}

    public function precision(): float
    {
        $retrieved = $this->truePositives + $this->falsePositives;

        return 0 === $retrieved ? 1.0 : $this->truePositives / $retrieved;
    }

    public function recall(): float
    {
        $relevant = $this->truePositives + $this->falseNegatives;

        return 0 === $relevant ? 1.0 : $this->truePositives / $relevant;
    }

    public function f1(): float
    {
        $precision = $this->precision();
        $recall = $this->recall();

        return 0.0 === $precision + $recall ? 0.0 : 2 * $precision * $recall / ($precision + $recall);
    }
}
