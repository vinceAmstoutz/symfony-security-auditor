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
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FindingOverlap
{
    /**
     * Returns the findings no finding of `$others` with the same file and type
     * overlaps.
     *
     * @param list<Vulnerability> $findings
     * @param list<Vulnerability> $others
     *
     * @return list<Vulnerability>
     */
    public static function outside(array $findings, array $others): array
    {
        $othersBySubject = [];
        foreach ($others as $other) {
            $othersBySubject[self::subject($other)][] = $other;
        }

        return array_values(array_filter(
            $findings,
            static fn (Vulnerability $finding): bool => !self::overlapsAny($finding, $othersBySubject[self::subject($finding)] ?? []),
        ));
    }

    private static function subject(Vulnerability $vulnerability): string
    {
        return \sprintf('%s:%s', $vulnerability->type()->value, $vulnerability->filePath());
    }

    /**
     * @param list<Vulnerability> $others
     */
    private static function overlapsAny(Vulnerability $finding, array $others): bool
    {
        foreach ($others as $other) {
            if ($other->lineStart() <= $finding->lineEnd() && $finding->lineStart() <= $other->lineEnd()) {
                return true;
            }
        }

        return false;
    }
}
