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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Tooling\PHPUnit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\PHPUnit\UncoveredLines;

final class UncoveredLinesTest extends TestCase
{
    public function test_it_names_every_statement_that_never_executed(): void
    {
        self::assertSame(['src/A.php:19', 'src/B.php:7'], UncoveredLines::in($this->report()));
    }

    public function test_it_ignores_statements_that_did_execute(): void
    {
        self::assertNotContains('src/A.php:12', UncoveredLines::in($this->report()));
    }

    public function test_it_ignores_coverage_entries_that_are_not_statements(): void
    {
        self::assertNotContains('src/B.php:3', UncoveredLines::in($this->report()));
    }

    #[DataProvider('unusableReports')]
    public function test_it_names_nothing_from_a_report_it_cannot_read(string $report): void
    {
        self::assertSame([], UncoveredLines::in($report));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableReports(): iterable
    {
        yield 'not xml' => ['this is not a report'];
        yield 'truncated xml' => ['<coverage><project><file name="src/A.php">'];
        yield 'empty' => [''];
        yield 'fully covered' => ['<coverage><project><file name="src/A.php"><line num="1" type="stmt" count="3"/></file></project></coverage>'];
    }

    private function report(): string
    {
        return <<<'XML'
            <?xml version="1.0" encoding="UTF-8"?>
            <coverage>
                <project>
                    <file name="src/A.php">
                        <line num="12" type="stmt" count="1"/>
                        <line num="19" type="stmt" count="0"/>
                    </file>
                    <file name="src/B.php">
                        <line num="3" type="method" count="0"/>
                        <line num="7" type="stmt" count="0"/>
                    </file>
                    <metrics statements="4" coveredstatements="1"/>
                </project>
            </coverage>
            XML;
    }
}
