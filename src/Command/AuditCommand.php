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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\MapInput;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ConsoleProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;

#[AsCommand(
    name: 'audit:run',
    description: 'Run AI-powered multi-agent security audit on a Symfony project',
    help: <<<'HELP'
        The <info>%command.name%</info> command runs a multi-agent LLM security audit against a Symfony project.

        Output formats (<info>--format</info>, <info>-f</info>):
          <info>console</info>  human-readable summary (default)
          <info>json</info>     machine-readable report
          <info>sarif</info>    SARIF 2.1.0 for GitHub Code Scanning / GitLab Security Dashboard
          <info>html</info>     self-contained HTML report for sharing or archiving

        Use <info>--output</info> (<info>-o</info>) to write the report to a file:
          <info>%command.full_name% . --format=sarif --output=report.sarif</info>
          <info>%command.full_name% . --format=html --output=report.html</info>

        Baseline (suppress accepted findings):
          <info>%command.full_name% . --generate-baseline=.security-baseline.json</info>  accept current findings
          <info>%command.full_name% . --baseline=.security-baseline.json</info>           suppress them on later runs
        Baselined findings are dropped from the report and do not affect the exit code.

        Exit codes (the failure threshold is configurable via <info>audit.fail_on</info> / <info>--fail-on</info>, default <info>critical</info>):
          <info>0</info>  audit completed; risk level is below the fail-on threshold
          <info>1</info>  audit completed with risk level at or above the fail-on threshold, or the audit itself failed
          <info>2</info>  audit aborted because the configured token or cost budget was exceeded (partial report still emitted)

        Cost & duration: a typical Symfony project (~150 files) takes minutes, not seconds,
        and costs a few cents to a few dollars depending on the selected model. Configure
        via <info>config/packages/symfony_security_auditor.yaml</info>.

        Documentation:
          Configuration : <info>docs/configuration.md</info>
          CI integration: <info>docs/ci.md</info>
          Versioning    : <info>docs/versioning.md</info>
        HELP,
)]
/** @internal not part of the BC promise — the command *name* (`audit:run`) and its CLI surface are public, but the PHP class itself is for internal use only. */
final readonly class AuditCommand
{
    /**
     * @param list<string> $configNotices
     */
    public function __construct(
        private RunAuditUseCase $runAuditUseCase,
        private ReportWriterInterface $reportWriter,
        private AuditExitCodeResolverInterface $auditExitCodeResolver,
        private AuditPresenterInterface $auditPresenter,
        private EstimateAuditCostUseCase $estimateAuditCostUseCase,
        private ProgressReporterHolder $progressReporterHolder,
        private BaselineProcessorInterface $baselineProcessor,
        private bool $secretScrubbingEnabled,
        private array $configNotices = [],
        private RiskLevel $riskLevel = RiskLevel::Critical,
    ) {}

    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[MapInput] AuditCommandInput $auditCommandInput,
    ): int {
        $projectPath = $auditCommandInput->resolvedProjectPath();

        $this->auditPresenter->header($symfonyStyle, $projectPath);

        $this->auditPresenter->preflightWarnings($symfonyStyle, $this->secretScrubbingEnabled, $this->configNotices);

        $scanPaths = $auditCommandInput->scanPaths();

        try {
            if ($auditCommandInput->dryRun) {
                $this->auditPresenter->estimatingSection($symfonyStyle);
                $report = $this->estimateAuditCostUseCase->execute($projectPath, $scanPaths);

                $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $report);

                if ($auditCommandInput->isMachineReadableFormat()) {
                    $this->reportWriter->write($report, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);
                }

                if (!$auditCommandInput->isMachineReadableToStdout()) {
                    $this->auditPresenter->dryRunResult($symfonyStyle, $report);
                }

                return Command::SUCCESS;
            }

            $this->auditPresenter->runningSection($symfonyStyle);

            if (!$auditCommandInput->isMachineReadableToStdout()) {
                $this->auditPresenter->longRunNotice($symfonyStyle);
                $this->progressReporterHolder->setDelegate(new ConsoleProgressReporter($symfonyStyle));
            }

            $report = $this->runAuditUseCase->execute($projectPath, $scanPaths, $auditCommandInput->noCache, $auditCommandInput->since);

            if (null !== $auditCommandInput->generateBaseline) {
                $fingerprintCount = $this->baselineProcessor->generate($report, $auditCommandInput->generateBaseline);
                $this->reportWriter->write($report, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);

                if (!$auditCommandInput->isMachineReadableToStdout()) {
                    $this->auditPresenter->baselineGenerated($symfonyStyle, $auditCommandInput->generateBaseline, $fingerprintCount);
                }

                return Command::SUCCESS;
            }

            $baselineResult = $this->baselineProcessor->apply($report, $auditCommandInput->baseline);
            $report = $baselineResult->report;

            if (!$auditCommandInput->isMachineReadableToStdout()) {
                $this->auditPresenter->baselineApplied($symfonyStyle, $baselineResult->suppressedCount);
            }

            $this->reportWriter->write($report, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);

            $exitCode = $this->auditExitCodeResolver->resolve($report, $auditCommandInput->failOn ?? $this->riskLevel);

            if (!$auditCommandInput->isMachineReadableToStdout()) {
                $this->auditPresenter->result($symfonyStyle, $report, $exitCode);
            }

            return $exitCode;
        } catch (AuditAbortedByBudgetException $auditAbortedByBudgetException) {
            $partialReport = $auditAbortedByBudgetException->partialReport();
            $this->reportWriter->write($partialReport, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);
            $this->auditPresenter->error($symfonyStyle, $auditAbortedByBudgetException);

            return self::EXIT_CODE_BUDGET_ABORTED;
        } catch (Throwable $throwable) {
            $this->auditPresenter->error($symfonyStyle, $throwable);

            return Command::FAILURE;
        }
    }

    private const int EXIT_CODE_BUDGET_ABORTED = 2;
}
