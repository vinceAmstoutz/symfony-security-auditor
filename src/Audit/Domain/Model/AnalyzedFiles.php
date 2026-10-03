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
 * Reads a coverage ledger for the files the attacker analyzed, or served from
 * its cache, at least once. The attacker is the stage that reads a file whole,
 * so only its word says a file was looked at: the absence of a finding in any
 * other file — one the lean pre-scan skipped, one outside a `--since` or
 * `--path` scope, one whose call failed — proves nothing.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
