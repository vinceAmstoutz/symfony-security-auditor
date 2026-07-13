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
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineMerger;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoader;

final class BaselineCommandTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/baseline_command_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    public function test_it_creates_a_baseline_from_a_report(): void
    {
        $report = $this->writeReport([$this->vulnerability('SQL Injection')]);
        $baseline = $this->tmpDir.'/baseline.json';

        $commandTester = $this->commandTester();
        $commandTester->execute(['report' => $report, 'baseline' => $baseline]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('1 added, 0 kept, 0 pruned (1 entries).', $commandTester->getDisplay());
        self::assertSame(
            [
                [
                    'fingerprint' => $this->fingerprint('SQL Injection'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'SQL Injection',
                    'added_at' => '2026-07-13',
                ],
            ],
            $this->decode($baseline),
        );
    }

    public function test_updating_a_baseline_preserves_the_reason_of_an_existing_entry(): void
    {
        $report = $this->writeReport([$this->vulnerability('SQL Injection'), $this->vulnerability('XSS')]);
        $baseline = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($baseline, json_encode([
            [
                'fingerprint' => $this->fingerprint('SQL Injection'),
                'type' => 'sql_injection',
                'file' => 'src/Foo.php',
                'title' => 'SQL Injection',
                'added_at' => '2026-07-01',
                'reason' => 'input is validated upstream',
            ],
        ], \JSON_THROW_ON_ERROR));

        $commandTester = $this->commandTester();
        $commandTester->execute(['report' => $report, 'baseline' => $baseline]);

        self::assertStringContainsString('1 added, 1 kept, 0 pruned (2 entries).', $commandTester->getDisplay());
        self::assertSame(
            [
                [
                    'fingerprint' => $this->fingerprint('SQL Injection'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'SQL Injection',
                    'added_at' => '2026-07-01',
                    'reason' => 'input is validated upstream',
                ],
                [
                    'fingerprint' => $this->fingerprint('XSS'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'XSS',
                    'added_at' => '2026-07-13',
                ],
            ],
            $this->decode($baseline),
        );
    }

    public function test_prune_reports_how_many_stale_entries_were_dropped(): void
    {
        $report = $this->writeReport([]);
        $baseline = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($baseline, json_encode([
            [
                'fingerprint' => $this->fingerprint('Long Fixed'),
                'type' => 'sql_injection',
                'file' => 'src/Foo.php',
                'title' => 'Long Fixed',
                'added_at' => '2026-07-01',
            ],
        ], \JSON_THROW_ON_ERROR));

        $commandTester = $this->commandTester();
        $commandTester->execute(['report' => $report, 'baseline' => $baseline, '--prune' => true]);

        self::assertStringContainsString('0 added, 0 kept, 1 pruned (0 entries).', $commandTester->getDisplay());
        self::assertSame([], $this->decode($baseline));
    }

    public function test_annotate_asks_a_reason_per_new_finding_and_records_it(): void
    {
        $report = $this->writeReport([$this->vulnerability('SQL Injection')]);
        $baseline = $this->tmpDir.'/baseline.json';

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['handled by Doctrine parameter binding']);
        $commandTester->execute(['report' => $report, 'baseline' => $baseline, '--annotate' => true]);

        $display = $commandTester->getDisplay();
        self::assertStringContainsString('Reason for accepting "SQL Injection" in src/Foo.php', $display);
        self::assertSame(
            [
                [
                    'fingerprint' => $this->fingerprint('SQL Injection'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'SQL Injection',
                    'added_at' => '2026-07-13',
                    'reason' => 'handled by Doctrine parameter binding',
                ],
            ],
            $this->decode($baseline),
        );
    }

    public function test_an_empty_annotate_answer_skips_the_reason(): void
    {
        $report = $this->writeReport([$this->vulnerability('SQL Injection')]);
        $baseline = $this->tmpDir.'/baseline.json';

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['']);
        $commandTester->execute(['report' => $report, 'baseline' => $baseline, '--annotate' => true]);

        self::assertSame(
            [
                [
                    'fingerprint' => $this->fingerprint('SQL Injection'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'SQL Injection',
                    'added_at' => '2026-07-13',
                ],
            ],
            $this->decode($baseline),
        );
    }

    public function test_without_prune_a_stale_entry_survives(): void
    {
        $report = $this->writeReport([]);
        $baseline = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($baseline, json_encode([
            [
                'fingerprint' => $this->fingerprint('Long Fixed'),
                'type' => 'sql_injection',
                'file' => 'src/Foo.php',
                'title' => 'Long Fixed',
                'added_at' => '2026-07-01',
            ],
        ], \JSON_THROW_ON_ERROR));

        $commandTester = $this->commandTester();
        $commandTester->execute(['report' => $report, 'baseline' => $baseline]);

        self::assertStringContainsString('0 added, 1 kept, 0 pruned (1 entries).', $commandTester->getDisplay());
    }

    public function test_annotate_records_a_distinct_reason_per_new_finding(): void
    {
        $report = $this->writeReport([$this->vulnerability('SQL Injection'), $this->vulnerability('XSS')]);
        $baseline = $this->tmpDir.'/baseline.json';

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['bound parameters', 'autoescaped output']);
        $commandTester->execute(['report' => $report, 'baseline' => $baseline, '--annotate' => true]);

        self::assertSame(
            [
                [
                    'fingerprint' => $this->fingerprint('SQL Injection'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'SQL Injection',
                    'added_at' => '2026-07-13',
                    'reason' => 'bound parameters',
                ],
                [
                    'fingerprint' => $this->fingerprint('XSS'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'XSS',
                    'added_at' => '2026-07-13',
                    'reason' => 'autoescaped output',
                ],
            ],
            $this->decode($baseline),
        );
    }

    public function test_a_missing_report_fails_with_a_clear_error(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->execute(['report' => $this->tmpDir.'/absent.json', 'baseline' => $this->tmpDir.'/baseline.json']);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('exist or is not readable', $commandTester->getDisplay());
    }

    public function test_a_malformed_baseline_fails_with_a_clear_error(): void
    {
        $report = $this->writeReport([]);
        $baseline = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($baseline, '{not json');

        $commandTester = $this->commandTester();
        $commandTester->execute(['report' => $report, 'baseline' => $baseline]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('not valid JSON', $commandTester->getDisplay());
    }

    /**
     * @return array{type: string, file: string, title: string, severity: string, fingerprint: string}
     */
    private function vulnerability(string $title): array
    {
        return [
            'type' => 'sql_injection',
            'file' => 'src/Foo.php',
            'title' => $title,
            'severity' => 'high',
            'fingerprint' => $this->fingerprint($title),
        ];
    }

    private function fingerprint(string $title): string
    {
        return Vulnerability::fingerprintOf('sql_injection', 'src/Foo.php', $title);
    }

    /**
     * @param list<array<string, string>> $vulnerabilities
     */
    private function writeReport(array $vulnerabilities): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode(['vulnerabilities' => $vulnerabilities], \JSON_THROW_ON_ERROR));

        return $path;
    }

    /**
     * @return array<mixed, mixed>
     */
    private function decode(string $path): array
    {
        $decoded = json_decode((string) file_get_contents($path), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private function commandTester(): CommandTester
    {
        return new CommandTester(new BaselineCommand(new BaselineMerger(
            new ReportFindingsLoader($this->filesystem),
            new Baseline($this->filesystem),
            new MockClock('2026-07-13 12:00:00'),
        )));
    }
}
