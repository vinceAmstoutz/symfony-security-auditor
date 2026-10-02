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
 * Reads a coverage ledger for the files some stage set out to analyze and
 * never finished: its call failed (`errored`) or an abort stopped the run
 * before reaching it (`aborted`). The attacker revisits every file on each
 * iteration, so only its last word on a file counts; any other stage — the
 * reviewer judging one finding — loses that piece of work for good, so each
 * of its failures counts. Files the lean pre-scan left out on purpose
 * (`skipped`) are not among them.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class UnanalyzedFiles
{
    private const array UNANALYZED_STATUSES = ['errored', 'aborted'];

    /**
     * @param list<array{stage: string, file: string, status: string}> $coverage
     *
     * @return list<string>
     */
    public static function in(array $coverage): array
    {
        return array_values(array_unique([
            ...self::filesTheAttackerLastLeftUnanalyzed($coverage),
            ...self::filesAnotherStageLeftUnanalyzed($coverage),
        ]));
    }

    /**
     * @param list<array{stage: string, file: string, status: string}> $coverage
     *
     * @return list<string>
     */
    private static function filesTheAttackerLastLeftUnanalyzed(array $coverage): array
    {
        $lastEntryByFile = [];
        foreach ($coverage as $entry) {
            if (AgentRole::Attacker->value === $entry['stage']) {
                $lastEntryByFile[$entry['file']] = $entry;
            }
        }

        return self::unanalyzedFilesAmong(array_values($lastEntryByFile));
    }

    /**
     * @param list<array{stage: string, file: string, status: string}> $coverage
     *
     * @return list<string>
     */
    private static function filesAnotherStageLeftUnanalyzed(array $coverage): array
    {
        return self::unanalyzedFilesAmong(array_values(array_filter(
            $coverage,
            static fn (array $entry): bool => AgentRole::Attacker->value !== $entry['stage'],
        )));
    }

    /**
     * @param list<array{stage: string, file: string, status: string}> $entries
     *
     * @return list<string>
     */
    private static function unanalyzedFilesAmong(array $entries): array
    {
        $unanalyzed = array_filter(
            $entries,
            static fn (array $entry): bool => \in_array($entry['status'], self::UNANALYZED_STATUSES, true),
        );

        return array_column($unanalyzed, 'file');
    }
}
