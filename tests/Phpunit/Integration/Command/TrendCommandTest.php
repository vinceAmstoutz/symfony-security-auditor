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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiffer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportTrendAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendPresenter;

final class TrendCommandTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/trend_command_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    public function test_it_tracks_finding_counts_across_three_reports(): void
    {
        $persisting = $this->vulnerability('CSRF Missing', 'src/Controller/A.php');
        $fixedInThird = $this->vulnerability('SQL Injection', 'src/Repository/B.php');
        $first = $this->writeReport('first.json', [$persisting, $fixedInThird]);
        $second = $this->writeReport('second.json', [$persisting, $fixedInThird]);
        $third = $this->writeReport('third.json', [$persisting]);

        $commandTester = $this->commandTester();
        $commandTester->execute(['reports' => [$first, $second, $third]]);

        $display = $commandTester->getDisplay();
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('Trend (3 reports)', $display);
        self::assertStringContainsString('2 findings (0 new, 0 fixed)', $display);
        self::assertStringContainsString('1 findings (0 new, 1 fixed)', $display);
        self::assertStringContainsString('Summary: 2 → 1 findings (-1) across 3 reports.', $display);
    }

    public function test_fewer_than_two_reports_fails_with_a_clear_error(): void
    {
        $only = $this->writeReport('only.json', []);

        $commandTester = $this->commandTester();
        $commandTester->execute(['reports' => [$only]]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('at least two report files', $commandTester->getDisplay());
    }

    public function test_a_missing_report_file_fails_with_a_clear_error(): void
    {
        $first = $this->writeReport('first.json', []);

        $commandTester = $this->commandTester();
        $commandTester->execute(['reports' => [$first, $this->tmpDir.'/absent.json']]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('exist or is not readable', $commandTester->getDisplay());
    }

    public function test_malformed_json_input_fails_with_a_clear_error(): void
    {
        $first = $this->tmpDir.'/broken.json';
        $this->filesystem->dumpFile($first, '{not json');
        $second = $this->writeReport('second.json', []);

        $commandTester = $this->commandTester();
        $commandTester->execute(['reports' => [$first, $second]]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('valid JSON: Syntax error', $commandTester->getDisplay());
    }

    public function test_a_missing_report_file_with_json_format_writes_the_error_to_stderr_keeping_stdout_parseable(): void
    {
        $first = $this->writeReport('first.json', []);

        $commandTester = $this->commandTester();
        $commandTester->execute(
            ['reports' => [$first, $this->tmpDir.'/absent.json'], '--format' => 'json'],
            ['capture_stderr_separately' => true],
        );

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('exist or is not readable', $commandTester->getErrorOutput());
        self::assertSame('', trim($commandTester->getDisplay()));
    }

    public function test_json_format_outputs_the_trend_as_structured_json(): void
    {
        $first = $this->writeReport('first.json', []);
        $second = $this->writeReport('second.json', [$this->vulnerability('SSRF via Webhook', 'src/Service/C.php')]);

        $commandTester = $this->commandTester();
        $commandTester->execute(['reports' => [$first, $second], '--format' => 'json']);

        self::assertSame(
            [
                'points' => [
                    ['report' => $first, 'total' => 0, 'new' => null, 'fixed' => null],
                    ['report' => $second, 'total' => 1, 'new' => 1, 'fixed' => 0],
                ],
            ],
            json_decode($commandTester->getDisplay(), true),
        );
    }

    /**
     * @return array{type: string, file: string, title: string, severity: string, fingerprint: string}
     */
    private function vulnerability(string $title, string $file): array
    {
        return [
            'type' => 'sql_injection',
            'file' => $file,
            'title' => $title,
            'severity' => 'high',
            'fingerprint' => Vulnerability::fingerprintOf('sql_injection', $file, $title),
        ];
    }

    /**
     * @param list<array<string, string>> $vulnerabilities
     */
    private function writeReport(string $filename, array $vulnerabilities): string
    {
        $path = $this->tmpDir.'/'.$filename;
        $this->filesystem->dumpFile($path, json_encode(['vulnerabilities' => $vulnerabilities], \JSON_THROW_ON_ERROR));

        return $path;
    }

    private function commandTester(): CommandTester
    {
        return new CommandTester(new TrendCommand(new ReportTrendAnalyzer(new ReportDiffer($this->filesystem)), new TrendPresenter()));
    }
}
