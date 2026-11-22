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
 * The files a coverage ledger says the attacker analyzed, or served from its
 * cache, at least once. Only the attacker reads a file whole, so no other
 * stage's entry counts.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AnalyzedFiles
{
    private const array ANALYZED_STATUSES = ['analyzed', 'cached'];

    /**
     * @param list<array{stage: string, file: string, status: string}> $coverage
     *
     * @return list<string>
     */
    public static function in(array $coverage): array
    {
        $analyzed = array_filter(
            $coverage,
            static fn (array $entry): bool => AgentRole::Attacker->value === $entry['stage']
                && \in_array($entry['status'], self::ANALYZED_STATUSES, true),
        );

        return array_values(array_unique(array_column($analyzed, 'file')));
    }
}
