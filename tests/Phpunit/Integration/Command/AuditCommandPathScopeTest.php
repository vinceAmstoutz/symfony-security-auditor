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

/**
 * `--path` replaces `scan.included_paths` for the run: the more specific,
 * more recent instruction wins over the configuration.
 */
final class AuditCommandPathScopeTest extends TestCase
{
    private string $project;

    #[Override]
    protected function setUp(): void
    {
        $this->project = sys_get_temp_dir().'/audit_cmd_path_scope_'.uniqid('', true);
        mkdir($this->project.'/src/Controller', 0o777, true);
        mkdir($this->project.'/src/Service', 0o777, true);
        mkdir($this->project.'/vendor/acme', 0o777, true);
        file_put_contents($this->project.'/src/Controller/HomeAction.php', '<?php final class HomeAction {}');
        file_put_contents($this->project.'/src/Service/Mailer.php', '<?php final class Mailer {}');
        file_put_contents($this->project.'/vendor/acme/Lib.php', '<?php final class Lib {}');
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->project);
    }

    public function test_a_path_wider_than_the_configured_scope_audits_every_file_under_it(): void
    {
        $commandTester = $this->makeCommandTester(['src/Controller']);

        $commandTester->execute(['project-path' => $this->project, '--path' => ['src'], '--show-scanned' => true]);

        $display = preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '';
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('src/Controller/HomeAction.php', $display);
        self::assertStringContainsString('src/Service/Mailer.php', $display);
        self::assertStringContainsString('2 file(s) in scope', $display);
    }

    public function test_the_project_root_as_a_path_keeps_the_configured_scope(): void
    {
        $commandTester = $this->makeCommandTester(['src/Controller']);

        $commandTester->execute(['project-path' => $this->project, '--path' => ['.'], '--show-scanned' => true]);

        $display = preg_replace('/\s+/', ' ', $commandTester->getDisplay()) ?? '';
        self::assertStringContainsString('src/Controller/HomeAction.php', $display);
        self::assertStringNotContainsString('vendor/acme/Lib.php', $display);
        self::assertStringContainsString('1 file(s) in scope', $display);
    }

    /**
     * @param list<string> $includedPaths
     */
    private function makeCommandTester(array $includedPaths): CommandTester
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/../UseCase/Fixture/pricing-catalog.json');
        $projectFileScanner = new ProjectFileScanner(new NullLogger(), $includedPaths);

        return new CommandTester(new AuditCommand(
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
        ));
    }
}
