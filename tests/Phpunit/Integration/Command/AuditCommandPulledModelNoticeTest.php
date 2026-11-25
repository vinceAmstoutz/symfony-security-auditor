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
use PHPUnit\Framework\MockObject\Rule\InvokedCount;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelNotice;
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

/**
 * A `--min-score` outside the 0 to 100 range of the normalized score runs the
 * audit as given, the command saying what the value does instead of refusing
 * it.
 */
final class AuditCommandPulledModelNoticeTest extends TestCase
{
    private const string NOTICE = 'The Ollama server at http://localhost:11434 has not pulled the model "qwen9"';

    private string $fixtureDir;

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/audit_cmd_pulled_model_'.uniqid('', true);
        mkdir($this->fixtureDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->fixtureDir);
    }

    public function test_a_run_on_ollama_names_a_configured_model_the_server_has_not_pulled_and_still_runs(): void
    {
        $pipeline = $this->createMock(PipelineInterface::class);
        $pipeline->expects(self::once())->method('process');

        $commandTester = $this->makeCommandTester($pipeline, $this->pulledModelList(self::once()));
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString(self::NOTICE, preg_replace('/\s+/', ' ', str_replace('!', '', $commandTester->getDisplay())) ?? '');
    }

    public function test_a_dry_run_does_not_ask_the_server(): void
    {
        $pipeline = $this->createMock(PipelineInterface::class);
        $pipeline->expects(self::never())->method('process');

        $commandTester = $this->makeCommandTester($pipeline, $this->pulledModelList(self::never()));
        $commandTester->execute(['project-path' => $this->fixtureDir, '--dry-run' => true]);

        self::assertStringNotContainsString('has not pulled', $commandTester->getDisplay());
    }

    private function pulledModelList(InvokedCount $invokedCount): PulledModelListInterface
    {
        $pulledModelList = $this->createMock(PulledModelListInterface::class);
        $pulledModelList->expects($invokedCount)->method('pulledModels')->willReturn(['qwen3:latest']);

        return $pulledModelList;
    }

    private function makeCommandTester(PipelineInterface $pipeline, PulledModelListInterface $pulledModelList): CommandTester
    {
        $pricingCatalog = __DIR__.'/../UseCase/Fixture/pricing-catalog.json';
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), $pricingCatalog);
        $projectFileScanner = new ProjectFileScanner(new NullLogger());

        return new CommandTester(new AuditCommand(
            new RunAuditUseCase($pipeline, new NullLogger()),
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
            pulledModelNotice: new PulledModelNotice($pulledModelList, 'http://localhost:11434', ['qwen9']),
        ));
    }
}
