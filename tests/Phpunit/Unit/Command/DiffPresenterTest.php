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

    public function test_console_output_renders_finding_title_literally_instead_of_as_console_markup(): void
    {
        $bufferedOutput = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true);
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $diffFinding = new DiffFinding('fingerprint', 'sql_injection', 'src/Foo.php', 'Bad <fg=grey>debug</> title', 'high');

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([$diffFinding], [], []), DiffOutputFormat::Console);

        self::assertStringContainsString('Bad <fg=grey>debug</> title', $bufferedOutput->fetch());
    }

    public function test_console_output_collapses_control_characters_in_a_finding_title_so_it_cannot_forge_a_line_or_spoof_the_terminal(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $diffFinding = new DiffFinding('fingerprint', 'sql_injection', 'src/Foo.php', "Benign\n  [CRITICAL] forged (x)\x1b[31m\u{202E}spoof", 'low');

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([$diffFinding], [], []), DiffOutputFormat::Console);
        $output = $bufferedOutput->fetch();

        self::assertDoesNotMatchRegularExpression('/^\s*\[CRITICAL] forged/m', $output);
        self::assertStringNotContainsString("\x1b", $output);
        self::assertStringNotContainsString("\u{202E}", $output);
    }

    private function finding(string $severity = 'high'): DiffFinding
    {
        return new DiffFinding('fingerprint', 'sql_injection', 'src/Foo.php', 'SQL Injection', $severity);
    }
}
