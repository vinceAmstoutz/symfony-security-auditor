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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AnalyzedFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ScanSkippedFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\UnanalyzedFiles;

final class ScanSkippedFilesTest extends TestCase
{
    public function test_it_drops_only_the_skipped_entries_of_the_scan_stage_and_keeps_the_ledger_a_list(): void
    {
        $coverage = [
            ['stage' => 'attacker', 'file' => 'src/Analyzed.php', 'status' => 'analyzed'],
            ['stage' => 'scan', 'file' => 'src/Big.php', 'status' => 'skipped'],
            ['stage' => 'attacker', 'file' => 'src/LeanSkipped.php', 'status' => 'skipped'],
            ['stage' => 'scan', 'file' => 'src/Errored.php', 'status' => 'errored'],
            ['stage' => 'reviewer', 'file' => 'src/Reviewed.php', 'status' => 'skipped'],
        ];

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Analyzed.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'file' => 'src/LeanSkipped.php', 'status' => 'skipped'],
                ['stage' => 'scan', 'file' => 'src/Errored.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/Reviewed.php', 'status' => 'skipped'],
            ],
            ScanSkippedFiles::without($coverage),
        );
    }

    public function test_a_ledger_without_a_skipped_scan_entry_comes_back_as_it_was(): void
    {
        $coverage = [['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'analyzed']];

        self::assertSame($coverage, ScanSkippedFiles::without($coverage));
        self::assertSame([], ScanSkippedFiles::without([]));
    }

    public function test_neither_the_analyzed_nor_the_unanalyzed_files_include_a_file_the_scan_left_out(): void
    {
        $coverage = [
            ['stage' => 'scan', 'file' => 'src/Big.php', 'status' => 'skipped'],
            ['stage' => 'attacker', 'file' => 'src/Small.php', 'status' => 'analyzed'],
        ];

        self::assertSame([], UnanalyzedFiles::in($coverage));
        self::assertSame(['src/Small.php'], AnalyzedFiles::in($coverage));
    }
}
