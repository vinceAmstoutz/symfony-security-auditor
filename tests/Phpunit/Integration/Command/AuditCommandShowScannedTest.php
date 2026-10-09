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
use Psr\Log\NullLogger;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\NothingAnalyzedPipeline;

final class AuditCommandShowScannedTest extends TestCase
{
    private string $fixtureDir;

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/audit_cmd_show_scanned_'.uniqid('', true);
        mkdir($this->fixtureDir.'/src', 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->fixtureDir);
    }

    public function test_show_scanned_names_the_project_and_lists_nothing_when_no_file_matches(): void
    {
        $commandTester = $this->makeCommandTester();
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--show-scanned' => true,
        ]);

        $display = preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '';
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('No files matched under "'.$this->fixtureDir.'".', $display);
        self::assertStringNotContainsString('file(s) in scope', $display);
    }

    public function test_show_scanned_lists_the_matching_files_without_the_no_match_notice(): void
    {
        file_put_contents($this->fixtureDir.'/src/Repo.php', '<?php class Repo {}');

        $commandTester = $this->makeCommandTester();
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--show-scanned' => true,
        ]);

        $display = preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '';
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('src/Repo.php', $display);
        self::assertStringContainsString('1 file(s) in scope', $display);
        self::assertStringNotContainsString('No files matched', $display);
    }

    public function test_it_audits_the_working_directory_when_its_name_is_not_valid_utf8(): void
    {
        $project = $this->fixtureDir."/jos\xE9";
        mkdir($project.'/src', 0o777, true);
        file_put_contents($project.'/src/Repo.php', '<?php class Repo {}');
        $commandTester = $this->makeCommandTester();

        $previousDirectory = getcwd();
        self::assertNotFalse($previousDirectory);
        chdir($project);

        try {
            $commandTester->execute(['--show-scanned' => true]);
        } finally {
            chdir($previousDirectory);
        }

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('src/Repo.php', preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '');
    }

    public function test_it_audits_an_explicit_project_path_whose_name_is_not_valid_utf8(): void
    {
        $project = $this->fixtureDir."/jos\xE9";
        mkdir($project.'/src', 0o777, true);
        file_put_contents($project.'/src/Repo.php', '<?php class Repo {}');
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $project, '--show-scanned' => true]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('src/Repo.php', preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '');
    }

    public function test_it_accepts_a_scan_path_whose_name_is_not_valid_utf8(): void
    {
        mkdir($this->fixtureDir."/src/caf\xE9", 0o777, true);
        file_put_contents($this->fixtureDir."/src/caf\xE9/Repo.php", '<?php class Repo {}');
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->fixtureDir, '--path' => ["src/caf\xE9"], '--show-scanned' => true]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('1 file(s) in scope', preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '');
    }

    private function makeCommandTester(): CommandTester
    {
        $pricingCatalog = __DIR__.'/../UseCase/Fixture/pricing-catalog.json';
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), $pricingCatalog);
        $projectFileScanner = new ProjectFileScanner(new NullLogger());

        $auditCommand = new AuditCommand(
            new RunAuditUseCase(new NothingAnalyzedPipeline(), new NullLogger()),
            new ReportWriter([new JsonReportRenderer()], new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter($modelsDevPricingProvider),
            new EstimateAuditCostUseCase($projectFileScanner, new ResolvingTokenEstimator(), new CostCalculator($modelsDevPricingProvider), new NullLogger(), new FileChunker(), new AttackerSkillRegistry(), 'stub', 1),
            new ListScannedFilesUseCase($projectFileScanner),
            new ProgressReporterHolder(new NullLogger()),
            new AuditedProjectPathHolder('/app'),
            new BaselineProcessor(new Baseline()),
            new UnpricedModelBudgetGuard($modelsDevPricingProvider, ['stub']),
            new ReviewerFeedbackHolder(),
            secretScrubbingEnabled: true,
            findingTypeFilter: new FindingTypeFilter([], []),
        );

        return new CommandTester($auditCommand);
    }
}
