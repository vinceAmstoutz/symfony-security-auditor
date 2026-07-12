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
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiffer;

final class DiffCommandTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/diff_command_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    public function test_it_lists_new_fixed_and_persisting_findings(): void
    {
        $persisting = $this->vulnerability('CSRF Missing', 'src/Controller/A.php');
        $fixed = $this->vulnerability('SQL Injection', 'src/Repository/B.php');
        $new = $this->vulnerability('SSRF via Webhook', 'src/Service/C.php');

        $previous = $this->writeReport('previous.json', [$persisting, $fixed]);
        $current = $this->writeReport('current.json', [$persisting, $new]);

        $commandTester = $this->commandTester();
        $commandTester->execute(['previous-report' => $previous, 'current-report' => $current]);

        $display = $commandTester->getDisplay();
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('SSRF via Webhook', $display);
        self::assertStringContainsString('SQL Injection', $display);
        self::assertStringContainsString('CSRF Missing', $display);
        self::assertStringContainsString('Summary: 1 new, 1 fixed, 1 persisting.', $display);
    }

    public function test_empty_diff_of_identical_reports_reports_zero_counts(): void
    {
        $vulnerability = $this->vulnerability('CSRF Missing', 'src/Controller/A.php');
        $previous = $this->writeReport('previous.json', [$vulnerability]);
        $current = $this->writeReport('current.json', [$vulnerability]);

        $commandTester = $this->commandTester();
        $commandTester->execute(['previous-report' => $previous, 'current-report' => $current]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('Summary: 0 new, 0 fixed, 1 persisting.', $commandTester->getDisplay());
    }

    public function test_it_treats_a_report_missing_the_fingerprint_key_as_persisting_when_unchanged(): void
    {
        $vulnerability = $this->vulnerability('CSRF Missing', 'src/Controller/A.php');
        unset($vulnerability['fingerprint']);
        $previous = $this->writeReport('previous.json', [$vulnerability]);
        $current = $this->writeReport('current.json', [$vulnerability]);

        $commandTester = $this->commandTester();
        $commandTester->execute(['previous-report' => $previous, 'current-report' => $current]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('Summary: 0 new, 0 fixed, 1 persisting.', $commandTester->getDisplay());
    }

    public function test_malformed_json_input_fails_with_a_clear_error(): void
    {
        $previous = $this->tmpDir.'/broken.json';
        $this->filesystem->dumpFile($previous, '{not json');
        $current = $this->writeReport('current.json', []);

        $commandTester = $this->commandTester();
        $commandTester->execute(['previous-report' => $previous, 'current-report' => $current]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('valid JSON: Syntax error', $commandTester->getDisplay());
    }

    public function test_a_missing_report_file_fails_with_a_clear_error(): void
    {
        $current = $this->writeReport('current.json', []);

        $commandTester = $this->commandTester();
        $commandTester->execute(['previous-report' => $this->tmpDir.'/absent.json', 'current-report' => $current]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('exist or is not readable', $commandTester->getDisplay());
    }

    public function test_a_missing_report_file_with_json_format_writes_the_error_to_stderr_keeping_stdout_parseable(): void
    {
        $current = $this->writeReport('current.json', []);

        $commandTester = $this->commandTester();
        $commandTester->execute(
            ['previous-report' => $this->tmpDir.'/absent.json', 'current-report' => $current, '--format' => 'json'],
            ['capture_stderr_separately' => true],
        );

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('exist or is not readable', $commandTester->getErrorOutput());
        self::assertSame('', trim($commandTester->getDisplay()));
    }

    public function test_json_format_outputs_the_diff_as_structured_json(): void
    {
        $new = $this->vulnerability('SSRF via Webhook', 'src/Service/C.php');
        $previous = $this->writeReport('previous.json', []);
        $current = $this->writeReport('current.json', [$new]);

        $commandTester = $this->commandTester();
        $commandTester->execute([
            'previous-report' => $previous,
            'current-report' => $current,
            '--format' => 'json',
        ]);

        $decoded = json_decode($commandTester->getDisplay(), true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('new', $decoded);
        self::assertArrayHasKey('fixed', $decoded);
        self::assertArrayHasKey('persisting', $decoded);

        $newFindings = $decoded['new'];
        self::assertIsArray($newFindings);
        self::assertCount(1, $newFindings);

        $firstNewFinding = $newFindings[0];
        self::assertIsArray($firstNewFinding);
        self::assertSame('SSRF via Webhook', $firstNewFinding['title']);
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
        return new CommandTester(new DiffCommand(new ReportDiffer($this->filesystem), new DiffPresenter()));
    }
}
