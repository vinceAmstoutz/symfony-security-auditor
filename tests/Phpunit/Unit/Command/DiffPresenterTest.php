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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffFinding;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffOutputFormat;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiff;

final class DiffPresenterTest extends TestCase
{
    private DiffPresenter $diffPresenter;

    #[Override]
    protected function setUp(): void
    {
        $this->diffPresenter = new DiffPresenter();
    }

    public function test_it_prints_the_section_header_with_the_finding_count(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([$this->finding()], [], []), DiffOutputFormat::Console);

        self::assertStringContainsString('New (1)', $bufferedOutput->fetch());
    }

    public function test_it_prints_none_for_a_section_with_no_findings(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([], [], []), DiffOutputFormat::Console);

        self::assertStringContainsString('(none)', $bufferedOutput->fetch());
    }

    public function test_it_does_not_print_none_for_a_section_with_findings(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([$this->finding()], [$this->finding()], [$this->finding()]), DiffOutputFormat::Console);

        self::assertStringNotContainsString('(none)', $bufferedOutput->fetch());
    }

    public function test_it_uppercases_the_severity_label(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([$this->finding(severity: 'high')], [], []), DiffOutputFormat::Console);

        self::assertStringContainsString('[HIGH]', $bufferedOutput->fetch());
    }

    private function finding(string $severity = 'high'): DiffFinding
    {
        return new DiffFinding('fingerprint', 'sql_injection', 'src/Foo.php', 'SQL Injection', $severity);
    }
}
