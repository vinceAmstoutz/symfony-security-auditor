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

use JsonException;
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

    public function test_console_output_defuses_a_legacy_workflow_command_in_a_finding(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $diffFinding = new DiffFinding('fingerprint', 'sql_injection', 'src/##[warning]Y.php', 't ##[error]X', 'high');

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([$diffFinding], [], []), DiffOutputFormat::Console);

        $output = $bufferedOutput->fetch();
        self::assertStringContainsString('t #\\#[error]X', $output);
        self::assertStringContainsString('src/#\\#[warning]Y.php', $output);
        self::assertStringNotContainsString('##[', $output);
    }

    public function test_json_output_defuses_a_legacy_workflow_command_and_keeps_its_meaning(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $diffFinding = new DiffFinding('fingerprint', 'sql_injection', 'src/Foo.php', 't ##[error]X', 'high');

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([$diffFinding], [], []), DiffOutputFormat::Json);

        $output = $bufferedOutput->fetch();
        self::assertStringNotContainsString('##[', $output);
        self::assertStringContainsString('"title": "t ##[error]X"', (string) json_encode(json_decode($output, true), \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES));
    }

    private function finding(string $severity = 'high'): DiffFinding
    {
        return new DiffFinding('fingerprint', 'sql_injection', 'src/Foo.php', 'SQL Injection', $severity);
    }

    public function test_it_prints_the_unverified_section_and_counts_it_in_the_summary(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([], [], [], [
            new DiffFinding('fp-unverified', 'sql_injection', 'src/Foo.php', 'SQL Injection', 'high'),
        ]), DiffOutputFormat::Console);

        $output = $bufferedOutput->fetch();

        self::assertStringContainsString('Unverified (1)', $output);
        self::assertStringContainsString('[HIGH] sql_injection — SQL Injection (src/Foo.php)', $output);
        self::assertStringContainsString('could not fully analyze their files — not shown as fixed', $output);
        self::assertStringContainsString('Summary: 0 new, 0 fixed, 1 unverified, 0 persisting.', $output);
    }

    public function test_it_leaves_the_unverified_section_out_when_every_disappearance_was_verified(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([], [], []), DiffOutputFormat::Console);

        $output = $bufferedOutput->fetch();

        self::assertStringNotContainsString('Unverified', $output);
        self::assertStringContainsString('Summary: 0 new, 0 fixed, 0 persisting.', $output);
    }

    /**
     * @throws JsonException
     */
    public function test_json_format_lists_the_unverified_findings_between_the_fixed_and_persisting_ones(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->diffPresenter->present($symfonyStyle, new ReportDiff([], [], [], [
            new DiffFinding('fp-unverified', 'sql_injection', 'src/Foo.php', 'SQL Injection', 'high'),
        ]), DiffOutputFormat::Json);

        $decoded = json_decode($bufferedOutput->fetch(), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertSame(['new', 'fixed', 'unverified', 'persisting'], array_keys($decoded));
        self::assertSame([['fingerprint' => 'fp-unverified', 'type' => 'sql_injection', 'file' => 'src/Foo.php', 'title' => 'SQL Injection', 'severity' => 'high']], $decoded['unverified']);
    }
}
