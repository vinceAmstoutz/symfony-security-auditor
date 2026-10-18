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
use PHPUnit\Framework\Attributes\DataProvider;
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

final class AuditCommandFolderOfProjectTest extends TestCase
{
    private string $workspace;

    private string $project;

    #[Override]
    protected function setUp(): void
    {
        $this->workspace = sys_get_temp_dir().'/audit_cmd_folder_of_project_'.uniqid('', true);
        $this->project = $this->workspace.'/site';
        mkdir($this->project.'/src/Controller', 0o777, true);
        mkdir($this->project.'/config/packages', 0o777, true);
        file_put_contents($this->project.'/composer.json', '{}');
        file_put_contents($this->project.'/src/Controller/HomeAction.php', '<?php final class HomeAction {}');
        file_put_contents($this->project.'/src/Kernel.php', '<?php final class Kernel {}');
        file_put_contents($this->project.'/config/packages/security.yaml', "security:\n    firewalls: { main: ~ }\n");
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->workspace);
    }

    public function test_a_folder_of_a_project_is_audited_as_that_project_scoped_to_the_folder(): void
    {
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->project.'/src', '--show-scanned' => true]);

        $display = $this->display($commandTester);
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString(\sprintf('Project: %s ', $this->project), $display);
        self::assertStringContainsString('* src/Controller/HomeAction.php', $display);
        self::assertStringContainsString('* src/Kernel.php', $display);
        self::assertStringContainsString('2 file(s) in scope', $display);
    }

    public function test_it_says_which_project_it_audits_in_place_of_the_folder_named(): void
    {
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->project.'/src', '--show-scanned' => true]);

        self::assertStringContainsString(\sprintf('[NOTE] Auditing "%1$s" --path src: "%1$s/src" is not a project root, it holds no composer.json.', $this->project), $this->display($commandTester));
    }

    public function test_it_names_no_path_when_the_path_given_is_the_project_itself(): void
    {
        $commandTester = $this->makeCommandTester();

        $this->inWorkspace(fn (): int => $commandTester->execute(['--path' => [$this->project], '--show-scanned' => true]));

        $display = $this->display($commandTester);
        self::assertStringContainsString(\sprintf('[NOTE] Auditing "%s": "%s" is not a project root, it holds no composer.json.', $this->project, $this->workspace), $display);
        self::assertStringContainsString('* config/packages/security.yaml', $display);
        self::assertStringContainsString('3 file(s) in scope', $display);
    }

    public function test_it_says_nothing_about_a_project_named_as_such(): void
    {
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->project, '--path' => ['src'], '--show-scanned' => true]);

        self::assertStringNotContainsString('is not a project root', $this->display($commandTester));
    }

    public function test_a_path_given_with_a_folder_of_a_project_is_read_relative_to_that_folder(): void
    {
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->project.'/src', '--path' => ['Controller', 'Kernel.php'], '--show-scanned' => true]);

        $display = $this->display($commandTester);
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString(\sprintf('Project: %s ', $this->project), $display);
        self::assertStringContainsString('controller (1) * src/Controller/HomeAction.php', $display);
        self::assertStringContainsString('* src/Kernel.php', $display);
        self::assertStringContainsString('2 file(s) in scope', $display);
    }

    public function test_a_folder_holding_a_default_scan_path_stays_the_project_inside_a_composer_project(): void
    {
        mkdir($this->project.'/apps/api/src', 0o777, true);
        file_put_contents($this->project.'/apps/api/src/ApiAction.php', '<?php final class ApiAction {}');
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->project.'/apps/api', '--show-scanned' => true]);

        $display = $this->display($commandTester);
        self::assertStringContainsString(\sprintf('Project: %s/apps/api ', $this->project), $display);
        self::assertStringContainsString('* src/ApiAction.php', $display);
    }

    public function test_a_folder_the_configured_scan_finds_files_in_stays_the_project_as_in_1_21(): void
    {
        mkdir($this->project.'/packages/legacy/lib', 0o777, true);
        file_put_contents($this->project.'/packages/legacy/lib/Legacy.php', '<?php final class Legacy {}');
        $commandTester = $this->makeCommandTester(['lib']);

        $commandTester->execute(['project-path' => $this->project.'/packages/legacy', '--show-scanned' => true]);

        $display = $this->display($commandTester);
        self::assertStringContainsString(\sprintf('Project: %s/packages/legacy ', $this->project), $display);
        self::assertStringContainsString('* lib/Legacy.php', $display);
        self::assertStringNotContainsString('is not a project root', $display);
    }

    public function test_a_directory_holding_a_composer_json_stays_the_project_even_with_nothing_to_scan(): void
    {
        mkdir($this->project.'/packages/tool', 0o777, true);
        file_put_contents($this->project.'/packages/tool/composer.json', '{}');
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->project.'/packages/tool', '--show-scanned' => true]);

        $display = $this->display($commandTester);
        self::assertStringContainsString(\sprintf('Project: %s/packages/tool ', $this->project), $display);
        self::assertStringContainsString('No files matched under', $display);
        self::assertStringNotContainsString('is not a project root', $display);
    }

    public function test_a_folder_no_composer_project_encloses_stays_the_project(): void
    {
        mkdir($this->workspace.'/notes/lib', 0o777, true);
        file_put_contents($this->workspace.'/notes/lib/Note.php', '<?php final class Note {}');
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->workspace.'/notes', '--show-scanned' => true]);

        $display = $this->display($commandTester);
        self::assertStringContainsString(\sprintf('Project: %s/notes ', $this->workspace), $display);
        self::assertStringContainsString(\sprintf('No files matched under "%s/notes".', $this->workspace), $display);
    }

    public function test_paths_into_two_projects_keep_the_named_directory_as_the_project(): void
    {
        mkdir($this->workspace.'/other/src', 0o777, true);
        file_put_contents($this->workspace.'/other/composer.json', '{}');
        file_put_contents($this->workspace.'/other/src/OtherAction.php', '<?php final class OtherAction {}');
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->workspace, '--path' => ['site/src', 'other/src'], '--show-scanned' => true]);

        $display = $this->display($commandTester);
        self::assertStringContainsString(\sprintf('Project: %s ', $this->workspace), $display);
        self::assertStringContainsString('* site/src/Controller/HomeAction.php', $display);
        self::assertStringContainsString('* other/src/OtherAction.php', $display);
    }

    public function test_a_mistyped_folder_of_a_project_is_refused_by_its_own_name(): void
    {
        $commandTester = $this->makeCommandTester();

        $commandTester->execute(['project-path' => $this->project.'/srcc', '--show-scanned' => true]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString(\sprintf('Project path "%s/srcc" is not a valid directory', $this->project), $this->display($commandTester));
    }

    #[DataProvider('pathsIntoTheProject')]
    public function test_a_path_into_a_project_from_a_directory_that_is_none_audits_that_project(string $path): void
    {
        $commandTester = $this->makeCommandTester();
        $scanPath = str_replace('{workspace}', $this->workspace, $path);

        $this->inWorkspace(static fn (): int => $commandTester->execute(['--path' => [$scanPath], '--show-scanned' => true]));

        $display = $this->display($commandTester);
        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString(\sprintf('Project: %s ', $this->project), $display);
        self::assertStringContainsString('controller (1) * src/Controller/HomeAction.php', $display);
        self::assertStringContainsString('1 file(s) in scope', $display);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function pathsIntoTheProject(): iterable
    {
        yield 'relative to the working directory' => ['site/src/Controller'];
        yield 'absolute' => ['{workspace}/site/src/Controller'];
    }

    /**
     * @param callable(): int $execute
     */
    private function inWorkspace(callable $execute): void
    {
        $previousDirectory = getcwd();
        self::assertNotFalse($previousDirectory);
        chdir($this->workspace);

        try {
            $execute();
        } finally {
            chdir($previousDirectory);
        }
    }

    private function display(CommandTester $commandTester): string
    {
        return preg_replace('/\s+/', ' ', str_replace(' ! ', ' ', $commandTester->getDisplay())) ?? '';
    }

    /**
     * @param list<string> $includedPaths
     */
    private function makeCommandTester(array $includedPaths = ProjectFileScanner::DEFAULT_INCLUDED_PATHS): CommandTester
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
