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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeReportWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsupportedOutputFormatException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ExitCode;
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture\ConnectionCutAfterToolAuditPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture\MalformedResponseAuditPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture\ScriptedAuditPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture\UnauthorizedAuditPlatform;

/**
 * Boots the real bundle through a Symfony kernel and drives `audit:run` from
 * the compiled container — the exact object graph `config/services.php` wires
 * for users — with only the `symfony/ai` platform replaced by the deterministic
 * {@see ScriptedAuditPlatform}. Unlike the hand-wired {@see FullAuditEndToEndTest},
 * this exercises `SymfonyAiLLMClient`, its retry/tool-loop/structured-collection
 * collaborators, and the DI defaults end to end, so production wiring drift and
 * report-schema drift both surface here.
 */
final class ContainerBackedAuditEndToEndTest extends TestCase
{
    private string $kernelDir;

    private string $fixtureDir;

    private ?Kernel $bootedKernel = null;

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_default_config_run_matches_the_committed_json_report_snapshot(): void
    {
        $report = $this->runAudit(['model' => 'gpt-4o'], 'json');

        self::assertSame(
            $this->snapshot('default-audit.json'),
            $this->normalizeJsonReport($report),
        );
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_json_report_printed_on_a_github_actions_runner_stays_the_same_document(): void
    {
        putenv('GITHUB_ACTIONS=true');

        $report = $this->runAudit(['model' => 'gpt-4o'], 'json');

        self::assertSame($this->snapshot('default-audit.json'), $this->normalizeJsonReport($report));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws UnsupportedOutputFormatException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_wired_report_writer_and_presenter_defuse_workflow_commands_on_a_github_actions_runner(): void
    {
        putenv('GITHUB_ACTIONS=true');
        $testContainer = $this->boot(['model' => 'gpt-4o'])->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);
        $reportWriter = $testContainer->get(ReportWriterInterface::class);
        self::assertInstanceOf(ReportWriterInterface::class, $reportWriter);
        $auditPresenter = $testContainer->get(AuditPresenterInterface::class);
        self::assertInstanceOf(AuditPresenterInterface::class, $auditPresenter);
        $auditContext = AuditContext::forProject($this->fixtureDir);
        $auditContext->addVulnerability(Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Finding', 0.9),
            new CodeLocation('src/A.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vec', "echo ok\n::stop-commands::pwned", 'fix'),
            'code',
        )->withReviewerValidation(true));
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $reportWriter->write(AuditReport::fromContext($auditContext), OutputFormat::Console, null, $symfonyStyle);
        $auditPresenter->error($symfonyStyle, new RuntimeException('src/a ::error::x.php'));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString(':\\:stop-commands::pwned', $display);
        self::assertStringContainsString('src/a :\\:error:\\:x.php', $display);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_default_config_run_matches_the_committed_sarif_report_snapshot(): void
    {
        $report = $this->runAudit(['model' => 'gpt-4o'], 'sarif');

        self::assertSame(
            $this->snapshot('default-audit.sarif.json'),
            $this->normalizeSarifReport($report),
        );
    }

    /**
     * Golden-masters every remaining `--format` renderer (console, executive,
     * html, markdown, junit, github, github-comment) written via `--output` — the clean
     * renderer output, free of presenter chrome and streamed progress — so a
     * change to any output format surfaces as a snapshot diff.
     */
    #[DataProvider('textReportFormatCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_default_config_run_matches_the_committed_text_report_snapshot(string $format, string $snapshot): void
    {
        self::assertSame(
            trim((string) file_get_contents(__DIR__.'/__snapshots__/'.$snapshot)),
            trim($this->normalizeTextReport($this->renderToFile(['model' => 'gpt-4o'], $format))),
        );
    }

    /** @return iterable<string, array{string, string}> */
    public static function textReportFormatCases(): iterable
    {
        yield 'console' => ['console', 'default-audit.console.txt'];
        yield 'executive' => ['executive', 'default-audit.executive.txt'];
        yield 'html' => ['html', 'default-audit.html'];
        yield 'markdown' => ['markdown', 'default-audit.markdown.txt'];
        yield 'junit' => ['junit', 'default-audit.junit.xml'];
        yield 'github' => ['github', 'default-audit.github.txt'];
        yield 'github-comment' => ['github-comment', 'default-audit.github-comment.txt'];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('configMatrixCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_seeded_finding_survives_every_wiring_combination(array $config): void
    {
        $report = $this->decode($this->runAudit(['model' => 'gpt-4o', ...$config], 'json'));

        self::assertSame(1, $report['total_vulnerabilities']);
    }

    /**
     * Each row swaps a different implementation behind the same public surface:
     * lean pre-scan + concurrency (`fast`), PoC synthesis (`thorough`), the
     * JSON-array collection fallback (attacker and reviewer), and batched
     * reviews. All must still surface — and validate — the seeded finding.
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function configMatrixCases(): iterable
    {
        yield 'fast profile (lean pre-scan + concurrency)' => [['profile' => 'fast']];
        yield 'thorough profile (poc synthesis)' => [['profile' => 'thorough']];
        yield 'json collection (attacker + reviewer)' => [['audit' => ['structured_collection' => false, 'reviewer_structured_collection' => false]]];
        yield 'json reviewer via explicit tools opt-out' => [['audit' => ['reviewer_structured_collection' => false, 'reviewer_tools_enabled' => false]]];
        yield 'batched reviews' => [['audit' => ['reviewer_batch_size' => 3]]];
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_cache_preserves_the_findings_across_a_second_run(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        $first = $this->normalizeFindings($this->execute($kernel, 'json'));
        $second = $this->normalizeFindings($this->execute($kernel, 'json'));

        self::assertSame($first, $second);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_second_run_is_served_from_the_attacker_cache(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        $this->execute($kernel, 'json');
        $secondRun = $this->decode($this->execute($kernel, 'json'));

        /** @var list<array{stage: string, status: string}> $coverage */
        $coverage = $secondRun['coverage'];
        self::assertContains('cached', array_column($coverage, 'status'));
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('collectionModeCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_provider_that_ignores_the_output_contract_degrades_to_a_finding_free_audit(array $config): void
    {
        $report = $this->decode($this->runAudit(['model' => 'gpt-4o', ...$config], 'json', MalformedResponseAuditPlatform::class));

        self::assertSame(0, $report['total_vulnerabilities']);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_report_written_after_the_provider_rejected_the_run_declares_itself_incomplete(): void
    {
        $report = $this->decode($this->runAudit(['model' => 'gpt-4o'], 'json', UnauthorizedAuditPlatform::class));

        self::assertFalse($report['complete']);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_concurrent_attacker_whose_retries_ran_out_after_a_tool_ran_aborts_the_run_like_the_sequential_one(): void
    {
        $commandTester = new CommandTester($this->auditCommand($this->boot(
            ['model' => 'gpt-4o', 'profile' => 'fast', 'audit' => ['retry' => ['max_attempts' => 2, 'initial_delay_ms' => 1, 'jitter_ratio' => 0.0]]],
            ConnectionCutAfterToolAuditPlatform::class,
        )));

        self::assertSame(ExitCode::Failure->value, $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => 'json']));
    }

    #[DataProvider('scopedRunFromOutsideCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_scoped_run_started_outside_the_project_audits_only_the_scoped_directory(string $workingFolder, string $projectArgument, string $pathArgument): void
    {
        $this->addVulnerableCommand();
        $base = \dirname($this->kernelDir);
        $workingDirectory = 'base' === $workingFolder ? $base : $base.'/elsewhere';
        (new Filesystem())->mkdir($workingDirectory);
        $previousWorkingDirectory = getcwd();
        self::assertNotFalse($previousWorkingDirectory);
        chdir($workingDirectory);

        try {
            $commandTester = new CommandTester($this->auditCommand($this->boot(['model' => 'gpt-4o'])));
            $commandTester->execute([
                'project-path' => 'absolute' === $projectArgument ? $this->fixtureDir : $projectArgument,
                '--path' => ['absolute' === $pathArgument ? $this->fixtureDir.'/src/Command' : $pathArgument],
                '--format' => 'json',
            ]);
        } finally {
            chdir($previousWorkingDirectory);
        }

        $report = $this->decode($commandTester->getDisplay());
        self::assertSame(1, $report['files_scanned']);
        self::assertSame(['since' => null, 'paths' => ['src/Command']], $report['scope']);
        self::assertSame(['src/Command/PurgeCommand.php'], $this->analyzedFiles($report));
        self::assertSame(['src/Command/PurgeCommand.php'], $this->filesWithFindings($report));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function scopedRunFromOutsideCases(): iterable
    {
        yield 'a relative path, the project named by its absolute path' => ['elsewhere', 'absolute', 'src/Command'];
        yield 'an absolute path inside the project' => ['elsewhere', 'absolute', 'absolute'];
        yield 'the project named relative to the working directory' => ['base', 'fixture', 'src/Command'];
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_path_outside_the_default_scan_surface_is_audited_when_the_flag_names_it(): void
    {
        (new Filesystem())->dumpFile(
            $this->fixtureDir.'/apps/api/src/ApiPurge.php',
            "<?php\nnamespace Api;\nclass ApiPurge\n{\n    public function __invoke(): int\n    {\n        // SECURITY_AUDITOR_SINK\n        return (int) unserialize(\$_SERVER['argv'][1]);\n    }\n}\n",
        );

        $commandTester = new CommandTester($this->auditCommand($this->boot(['model' => 'gpt-4o'])));
        $commandTester->execute(['project-path' => $this->fixtureDir, '--path' => ['apps/api'], '--format' => 'json']);

        $report = $this->decode($commandTester->getDisplay());
        self::assertSame(1, $report['files_scanned']);
        self::assertSame(['since' => null, 'paths' => ['apps/api']], $report['scope']);
        self::assertSame(['apps/api/src/ApiPurge.php'], $this->analyzedFiles($report));
        self::assertSame(['apps/api/src/ApiPurge.php'], $this->filesWithFindings($report));
    }

    #[DataProvider('failOnPrecedenceCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_fail_on_flag_wins_over_the_configured_fail_on(string $configured, ?string $flag, int $expectedExitCode): void
    {
        $commandTester = new CommandTester($this->auditCommand($this->boot(['model' => 'gpt-4o', 'audit' => ['fail_on' => $configured]])));
        $arguments = ['project-path' => $this->fixtureDir, '--format' => 'json'];

        self::assertSame($expectedExitCode, $commandTester->execute(null === $flag ? $arguments : [...$arguments, '--fail-on' => $flag]));
    }

    /**
     * @return iterable<string, array{string, ?string, int}>
     */
    public static function failOnPrecedenceCases(): iterable
    {
        yield 'the configured level alone, above the risk' => ['critical', null, 0];
        yield 'the configured level alone, at the risk' => ['low', null, 1];
        yield 'a flag that lowers the level below the risk' => ['critical', 'low', 1];
        yield 'a flag that raises the level above the risk' => ['low', 'critical', 0];
    }

    #[DataProvider('minScorePrecedenceCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_min_score_flag_wins_over_the_configured_min_score(int $configured, ?int $flag, int $expectedExitCode): void
    {
        $commandTester = new CommandTester($this->auditCommand($this->boot(['model' => 'gpt-4o', 'audit' => ['min_score' => $configured]])));
        $arguments = ['project-path' => $this->fixtureDir, '--format' => 'json'];

        self::assertSame($expectedExitCode, $commandTester->execute(null === $flag ? $arguments : [...$arguments, '--min-score' => $flag]));
    }

    /**
     * @return iterable<string, array{int, ?int, int}>
     */
    public static function minScorePrecedenceCases(): iterable
    {
        yield 'the configured score alone, above the score of the run' => [95, null, 1];
        yield 'the configured score alone, below the score of the run' => [50, null, 0];
        yield 'a flag that lowers the score below the run' => [95, 50, 0];
        yield 'a flag that raises the score above the run' => [50, 95, 1];
    }

    /**
     * @param list<string> $flags
     */
    #[DataProvider('failOnIncompletePrecedenceCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_fail_on_incomplete_flag_wins_over_the_configured_setting(bool $configured, array $flags, int $expectedExitCode): void
    {
        (new Filesystem())->dumpFile($this->fixtureDir.'/src/Service/Binary.php', "<?php // \xC3\x28\n");
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'scan' => ['secret_scrubbing' => ['enabled' => true, 'additional_patterns' => ['/NEVER_MATCHES/u']]],
            'audit' => ['fail_on_incomplete' => $configured],
        ]);
        $commandTester = new CommandTester($this->auditCommand($kernel));

        $exitCode = $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => 'json', ...array_fill_keys($flags, true)]);

        self::assertFalse($this->decode($commandTester->getDisplay())['complete']);
        self::assertSame($expectedExitCode, $exitCode);
    }

    /**
     * @return iterable<string, array{bool, list<string>, int}>
     */
    public static function failOnIncompletePrecedenceCases(): iterable
    {
        yield 'configured, no flag' => [true, [], 3];
        yield 'not configured, no flag' => [false, [], 0];
        yield 'configured, switched off by the flag' => [true, ['--no-fail-on-incomplete'], 0];
        yield 'not configured, switched on by the flag' => [false, ['--fail-on-incomplete'], 3];
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_format_flag_wins_over_the_configured_format_even_when_it_names_the_default(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['format' => 'json']]);

        $commandTester = $this->auditCommandTester($kernel);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        $overridden = $this->auditCommandTester($kernel);
        $overridden->execute(['project-path' => $this->fixtureDir, '--format' => 'console']);

        self::assertSame(3, $this->decode($commandTester->getDisplay())['files_scanned']);
        self::assertStringContainsString('RISK LEVEL', $overridden->getDisplay());
        self::assertStringNotContainsString('"files_scanned"', $overridden->getDisplay());
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_format_flag_clustered_with_other_flags_wins_over_the_configured_format(): void
    {
        $application = new Application();
        $application->addCommand($this->auditCommand($this->boot(['model' => 'gpt-4o', 'audit' => ['format' => 'sarif']])));

        $bufferedOutput = new BufferedOutput();

        $application->find('audit:run')->run(new StringInput(\sprintf('audit:run %s -nf json', escapeshellarg($this->fixtureDir))), $bufferedOutput);

        self::assertSame(3, $this->decode($bufferedOutput->fetch())['files_scanned']);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_dry_run_leaves_the_configured_output_alone(): void
    {
        $configuredOutput = $this->fixtureDir.'/configured.json';
        (new Filesystem())->dumpFile($configuredOutput, 'last real report');
        $commandTester = $this->auditCommandTester($this->boot(['model' => 'gpt-4o', 'audit' => ['format' => 'json', 'output' => $configuredOutput]]));

        $commandTester->execute(['project-path' => $this->fixtureDir, '--dry-run' => true]);

        self::assertSame('last real report', file_get_contents($configuredOutput));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_an_output_flag_wins_over_the_configured_output(): void
    {
        $configuredOutput = $this->fixtureDir.'/configured.json';
        $flagOutput = $this->fixtureDir.'/flag.json';
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['format' => 'json', 'output' => $configuredOutput]]);

        $this->auditCommandTester($kernel)->execute(['project-path' => $this->fixtureDir, '--output' => $flagOutput]);

        self::assertFileExists($flagOutput);
        self::assertFileDoesNotExist($configuredOutput);

        $this->auditCommandTester($kernel)->execute(['project-path' => $this->fixtureDir]);

        self::assertFileExists($configuredOutput);
        self::assertSame(3, $this->decode((string) file_get_contents($configuredOutput))['files_scanned']);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_no_output_flag_prints_the_report_although_an_output_is_configured(): void
    {
        $configuredOutput = $this->fixtureDir.'/configured.json';
        $commandTester = $this->auditCommandTester($this->boot(['model' => 'gpt-4o', 'audit' => ['format' => 'json', 'output' => $configuredOutput]]));

        $commandTester->execute(['project-path' => $this->fixtureDir, '--no-output' => true]);

        self::assertFileDoesNotExist($configuredOutput);
        self::assertSame(3, $this->decode($commandTester->getDisplay())['files_scanned']);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_no_output_flag_and_an_output_flag_together_are_refused_before_the_audit_runs(): void
    {
        $output = $this->fixtureDir.'/flag.json';
        $commandTester = $this->auditCommandTester($this->boot(['model' => 'gpt-4o']));

        $exitCode = $commandTester->execute(['project-path' => $this->fixtureDir, '--no-output' => true, '--output' => $output]);

        self::assertSame(ExitCode::Failure->value, $exitCode);
        self::assertStringContainsString('--output and --no-output cannot be combined', preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '');
        self::assertFileDoesNotExist($output);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_baseline_flag_wins_over_the_configured_baseline(): void
    {
        $configuredBaseline = $this->fixtureDir.'/configured-baseline.json';
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['baseline' => $configuredBaseline]]);
        $this->auditCommandTester($kernel)->execute(['project-path' => $this->fixtureDir, '--generate-baseline' => $configuredBaseline, '--format' => 'json']);

        $withTheConfiguredBaseline = $this->decode($this->execute($kernel, 'json'));
        $commandTester = $this->auditCommandTester($kernel);
        $commandTester->execute(['project-path' => $this->fixtureDir, '--baseline' => $this->fixtureDir.'/another-baseline.json', '--format' => 'json']);

        $withTheFlag = $this->decode($commandTester->getDisplay());

        self::assertSame(0, $withTheConfiguredBaseline['total_vulnerabilities']);
        self::assertSame(1, $withTheFlag['total_vulnerabilities']);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_no_cache_flag_wins_over_the_enabled_cache(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);
        $this->execute($kernel, 'json');

        $served = $this->decode($this->execute($kernel, 'json'));
        $commandTester = $this->auditCommandTester($kernel);
        $commandTester->execute(['project-path' => $this->fixtureDir, '--no-cache' => true, '--format' => 'json']);

        $bypassed = $this->decode($commandTester->getDisplay());

        self::assertContains('cached', $this->attackerStatuses($served));
        self::assertNotContains('cached', $this->attackerStatuses($bypassed));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_path_flag_wins_over_the_configured_included_paths(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'scan' => ['included_paths' => ['src/Service']]]);

        $configured = $this->decode($this->execute($kernel, 'json'));
        $commandTester = $this->auditCommandTester($kernel);
        $commandTester->execute(['project-path' => $this->fixtureDir, '--path' => ['src/Controller'], '--format' => 'json']);

        $overridden = $this->decode($commandTester->getDisplay());

        self::assertSame(['src/Service/Clean.php'], $this->analyzedFiles($configured));
        self::assertSame(['src/Controller/AdminController.php'], $this->analyzedFiles($overridden));
        self::assertSame(['src/Controller/AdminController.php'], $this->filesWithFindings($overridden));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_same_run_without_a_path_audits_every_directory_of_the_project(): void
    {
        $this->addVulnerableCommand();

        $report = $this->decode($this->runAudit(['model' => 'gpt-4o'], 'json'));

        self::assertSame(['src/Command/PurgeCommand.php', 'src/Controller/AdminController.php'], $this->filesWithFindings($report));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function collectionModeCases(): iterable
    {
        yield 'structured collection (tool calls)' => [[]];
        yield 'json collection (array fallback)' => [['audit' => ['structured_collection' => false, 'reviewer_structured_collection' => false]]];
    }

    private function auditCommandTester(Kernel $kernel): CommandTester
    {
        return new CommandTester($this->auditCommand($kernel));
    }

    /**
     * @param array<array-key, mixed> $report
     *
     * @return list<string>
     */
    private function attackerStatuses(array $report): array
    {
        $statuses = [];
        foreach ($this->entriesOf($report, 'coverage') as $entry) {
            if ('attacker' === $this->fieldOf($entry, 'stage')) {
                $statuses[] = $this->fieldOf($entry, 'status');
            }
        }

        return $statuses;
    }

    private function addVulnerableCommand(): void
    {
        (new Filesystem())->dumpFile(
            $this->fixtureDir.'/src/Command/PurgeCommand.php',
            "<?php\nnamespace App\\Command;\nclass PurgeCommand\n{\n    public function __invoke(): int\n    {\n        // SECURITY_AUDITOR_SINK\n        return (int) unserialize(\$_SERVER['argv'][1]);\n    }\n}\n",
        );
    }

    /**
     * @param array<array-key, mixed> $report
     *
     * @return list<string>
     */
    private function analyzedFiles(array $report): array
    {
        $analyzed = [];
        foreach ($this->entriesOf($report, 'coverage') as $entry) {
            if ('attacker' === $this->fieldOf($entry, 'stage') && 'analyzed' === $this->fieldOf($entry, 'status')) {
                $analyzed[] = $this->fieldOf($entry, 'file');
            }
        }

        $files = array_values(array_unique($analyzed));
        sort($files);

        return $files;
    }

    /**
     * @param array<array-key, mixed> $report
     *
     * @return list<string>
     */
    private function filesWithFindings(array $report): array
    {
        $files = array_values(array_unique(array_map(fn (mixed $entry): string => $this->fieldOf($entry, 'file'), $this->entriesOf($report, 'vulnerabilities'))));
        sort($files);

        return $files;
    }

    /**
     * @param array<array-key, mixed> $report
     *
     * @return array<array-key, mixed>
     */
    private function entriesOf(array $report, string $key): array
    {
        $entries = $report[$key] ?? null;
        self::assertIsArray($entries);

        return $entries;
    }

    private function fieldOf(mixed $entry, string $field): string
    {
        self::assertIsArray($entry);
        $value = $entry[$field] ?? null;
        self::assertIsString($value);

        return $value;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function normalizeFindings(string $report): array
    {
        $decoded = $this->decode($report);

        /** @var list<array<string, mixed>> $findings */
        $findings = $decoded['vulnerabilities'];

        return $this->stampTimestamps($findings);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function normalizeJsonReport(string $report): array
    {
        $decoded = $this->decode($report);
        $decoded['audit_id'] = 'AUDIT-XXXXXXXX';
        $decoded['project'] = 'PROJECT_PATH';
        $decoded['started_at'] = 'TIMESTAMP';
        $decoded['completed_at'] = 'TIMESTAMP';
        $decoded['duration_seconds'] = 'DURATION';

        /** @var list<array<string, mixed>> $vulnerabilities */
        $vulnerabilities = $decoded['vulnerabilities'];
        $decoded['vulnerabilities'] = $this->stampTimestamps($vulnerabilities);

        return $decoded;
    }

    /**
     * @param list<array<string, mixed>> $findings
     *
     * @return list<array<string, mixed>>
     */
    private function stampTimestamps(array $findings): array
    {
        return array_map(
            static fn (array $finding): array => [...$finding, 'detected_at' => 'TIMESTAMP'],
            $findings,
        );
    }

    /**
     * @return array<array-key, mixed>
     */
    private function normalizeSarifReport(string $report): array
    {
        /** @var array{runs: list<array{tool: array{driver: array<string, mixed>}}>} $decoded */
        $decoded = $this->decode($report);
        $decoded['runs'][0]['tool']['driver']['version'] = 'VERSION';

        return $decoded;
    }

    /**
     * Compares against the decoded snapshot rather than raw bytes, so the
     * committed file stays free to be Prettier-formatted without breaking the
     * assertion — the report's structure and values are what the golden master
     * pins.
     *
     * @return array<array-key, mixed>
     */
    private function snapshot(string $name): array
    {
        $decoded = json_decode((string) file_get_contents(__DIR__.'/__snapshots__/'.$name), true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function decode(string $report): array
    {
        $start = strpos($report, '{');
        $end = strrpos($report, '}');
        self::assertIsInt($start);
        self::assertIsInt($end);

        $decoded = json_decode(substr($report, $start, $end - $start + 1), true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * @param array<string, mixed>            $config
     * @param class-string<PlatformInterface> $platformClass
     */
    private function runAudit(array $config, string $format, string $platformClass = ScriptedAuditPlatform::class): string
    {
        return $this->execute($this->boot($config, $platformClass), $format);
    }

    private function execute(Kernel $kernel, string $format): string
    {
        $commandTester = new CommandTester($this->auditCommand($kernel));
        $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => $format]);

        return $commandTester->getDisplay();
    }

    /**
     * Renders through `--output` so the returned string is the renderer's file
     * output alone — no presenter header or streamed progress to strip.
     *
     * @param array<string, mixed> $config
     */
    private function renderToFile(array $config, string $format): string
    {
        $outputFile = $this->fixtureDir.'/report.out';
        $commandTester = new CommandTester($this->auditCommand($this->boot($config)));
        $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => $format, '--output' => $outputFile]);

        return (string) file_get_contents($outputFile);
    }

    private function auditCommand(Kernel $kernel): AuditCommand
    {
        $testContainer = $kernel->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);
        $auditCommand = $testContainer->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);

        return $auditCommand;
    }

    private function normalizeTextReport(string $report): string
    {
        $normalized = str_replace($this->fixtureDir, 'PROJECT_PATH', $report);
        $normalized = (string) preg_replace('/AUDIT-[0-9A-F]{8}/', 'AUDIT-XXXXXXXX', $normalized);
        $normalized = (string) preg_replace('/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/', 'TIMESTAMP', $normalized);

        return (string) preg_replace('/\d+\.\d+s/', 'DURATIONs', $normalized);
    }

    /**
     * @param array<string, mixed>            $bundleConfig
     * @param class-string<PlatformInterface> $platformClass
     */
    private function boot(array $bundleConfig, string $platformClass = ScriptedAuditPlatform::class): Kernel
    {
        $kernel = new class('test', true, $this->kernelDir, $bundleConfig, $platformClass) extends Kernel {
            /**
             * @param array<string, mixed>            $bundleConfig
             * @param class-string<PlatformInterface> $platformClass
             */
            public function __construct(string $environment, bool $debug, private readonly string $kernelDir, private readonly array $bundleConfig, private readonly string $platformClass)
            {
                parent::__construct($environment, $debug);
            }

            /**
             * @return iterable<FrameworkBundle|SymfonySecurityAuditorBundle>
             */
            #[Override]
            public function registerBundles(): iterable
            {
                yield new FrameworkBundle();
                yield new SymfonySecurityAuditorBundle();
            }

            #[Override]
            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $bundleConfig = $this->bundleConfig;
                $platformClass = $this->platformClass;
                $loader->load(static function (ContainerBuilder $containerBuilder) use ($bundleConfig, $platformClass): void {
                    $containerBuilder->loadFromExtension('framework', [
                        'secret' => 'test',
                        'http_method_override' => false,
                        'handle_all_throwables' => true,
                        'test' => true,
                        'validation' => ['email_validation_mode' => 'html5'],
                        'php_errors' => ['log' => true],
                    ]);
                    $containerBuilder->loadFromExtension('symfony_security_auditor', $bundleConfig);
                    $containerBuilder->register(PlatformInterface::class, $platformClass)->setPublic(true);
                });
            }

            #[Override]
            public function getProjectDir(): string
            {
                return $this->kernelDir;
            }

            #[Override]
            public function getCacheDir(): string
            {
                return $this->kernelDir.'/cache';
            }

            #[Override]
            public function getLogDir(): string
            {
                return $this->kernelDir.'/log';
            }
        };

        $kernel->boot();

        $this->bootedKernel = $kernel;

        return $kernel;
    }

    #[Override]
    protected function setUp(): void
    {
        $base = sys_get_temp_dir().'/container_e2e_'.uniqid('', true);
        $this->kernelDir = $base.'/kernel';
        $this->fixtureDir = $base.'/fixture';

        $filesystem = new Filesystem();
        $filesystem->mkdir([$this->kernelDir, $this->fixtureDir.'/src/Controller', $this->fixtureDir.'/src/Service', $this->fixtureDir.'/config']);

        $filesystem->dumpFile(
            $this->fixtureDir.'/src/Controller/AdminController.php',
            <<<'PHP'
                <?php
                namespace App\Controller;
                use Symfony\Component\HttpFoundation\Response;
                class AdminController
                {
                    public function delete(): Response
                    {
                        // SECURITY_AUDITOR_SINK
                        $payload = unserialize($_GET['payload']);

                        return new Response('deleted '.$payload);
                    }
                }
                PHP,
        );

        $filesystem->dumpFile(
            $this->fixtureDir.'/src/Service/Clean.php',
            <<<'PHP'
                <?php
                namespace App\Service;
                class Clean
                {
                    public function add(int $a, int $b): int
                    {
                        return $a + $b;
                    }
                }
                PHP,
        );

        $filesystem->dumpFile(
            $this->fixtureDir.'/config/security.yaml',
            "security:\n  firewalls:\n    main:\n      pattern: ^/\n",
        );
    }

    #[Override]
    protected function tearDown(): void
    {
        if ($this->bootedKernel instanceof Kernel) {
            $this->bootedKernel->shutdown();
            $this->bootedKernel = null;
        }

        $filesystem = new Filesystem();
        $base = \dirname($this->kernelDir);
        if ($filesystem->exists($base)) {
            $filesystem->remove($base);
        }
    }
}
