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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Which of two findings a collapse keeps: a reviewer-validated one over any
 * other, then the higher severity, then the higher confidence. A tie keeps the
 * incumbent, the finding seen first.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FindingPrecedence
{
    /**
     * @param list<Vulnerability> $findings
     *
     * @return list<Vulnerability> one finding per id, in the order each id first appeared
     */
    public static function collapseById(array $findings): array
    {
        $byId = [];
        foreach ($findings as $finding) {
            $kept = $byId[$finding->id()] ?? null;
            if (!$kept instanceof Vulnerability || self::prevails($finding, $kept)) {
                $byId[$finding->id()] = $finding;
            }
        }

        return array_values($byId);
    }

    public static function prevails(Vulnerability $challenger, Vulnerability $incumbent): bool
    {
        return self::rank($challenger) > self::rank($incumbent);
    }

    /**
     * @return array{bool, int, float}
     */
    private static function rank(Vulnerability $vulnerability): array
    {
        return [$vulnerability->isReviewerValidated(), $vulnerability->severity()->score(), $vulnerability->confidence()];
    }
}
