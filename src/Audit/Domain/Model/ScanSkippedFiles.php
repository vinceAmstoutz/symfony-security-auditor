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
 * How a coverage ledger records the files the scan matched and left out —
 * over the size limit, unreadable, sharing a repaired name: a `skipped` entry
 * under the `scan` stage. It informs, and nothing gates on it: neither
 * {@see UnanalyzedFiles} nor {@see AnalyzedFiles} reads it, so the report
 * stays complete, exactly as it did when such a file was silently dropped.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ScanSkippedFiles
{
    public const string STAGE = 'scan';

    public const string STATUS = 'skipped';

    /**
     * @param list<array{stage: string, file: string, status: string}> $coverage
     *
     * @return list<array{stage: string, file: string, status: string}> the ledger without the scan's `skipped` entries
     */
    public static function without(array $coverage): array
    {
        return array_values(array_filter(
            $coverage,
            static fn (array $entry): bool => self::STAGE !== $entry['stage'] || self::STATUS !== $entry['status'],
        ));
    }
}
