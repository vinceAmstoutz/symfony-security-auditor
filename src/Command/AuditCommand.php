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
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ConsoleProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\PlainProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsupportedOutputFormatException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\WorkingDirectoryUnavailableException;

#[AsCommand(
    name: self::NAME,
    description: self::DESCRIPTION,
    aliases: [self::ALIAS],
    help: AuditCommandHelp::HELP,
)]
/** @internal not part of the BC promise — the command *name* (`audit:run`), its `audit` alias, and the CLI surface are public, but the PHP class itself is for internal use only. */
final readonly class AuditCommand
{
    public const string NAME = 'audit:run';

    public const string ALIAS = 'audit';

    public const string DESCRIPTION = 'Run AI-powered multi-agent security audit on a Symfony project';

    /**
     * @param list<string> $configNotices
     */
    public function __construct(
        private RunAuditUseCase $runAuditUseCase,
        private ReportWriterInterface $reportWriter,
        private AuditExitCodeResolverInterface $auditExitCodeResolver,
        private AuditPresenterInterface $auditPresenter,
        private EstimateAuditCostUseCase $estimateAuditCostUseCase,
        private ListScannedFilesUseCase $listScannedFilesUseCase,
        private ProgressReporterHolder $progressReporterHolder,
        private BaselineProcessorInterface $baselineProcessor,
        private UnpricedModelBudgetGuardInterface $unpricedModelBudgetGuard,
        private bool $secretScrubbingEnabled,
        private FindingTypeFilterInterface $findingTypeFilter,
        private array $configNotices = [],
        private RiskLevel $riskLevel = RiskLevel::Critical,
    ) {}

    /**
     * @throws UnsupportedOutputFormatException
     * @throws WorkingDirectoryUnavailableException
     */
    public function __invoke(
        InputInterface $input,
        SymfonyStyle $symfonyStyle,
        #[MapInput] AuditCommandInput $auditCommandInput,
    ): int {
        $projectPath = $auditCommandInput->resolvedProjectPath();

        $this->auditPresenter->header($symfonyStyle, $projectPath);

        $this->auditPresenter->preflightWarnings($symfonyStyle, $this->secretScrubbingEnabled, $this->configNotices);

        $scanPaths = $auditCommandInput->scanPaths();

        try {
            if ($auditCommandInput->showScanned) {
                $this->showScannedFiles($symfonyStyle, $projectPath, $scanPaths);
            }

            if ($auditCommandInput->dryRun) {
                return $this->runDryRun($symfonyStyle, $auditCommandInput, $projectPath, $scanPaths);
            }

            if ($auditCommandInput->showScanned) {
                return ExitCode::Success->value;
            }

            if (!$this->unpricedModelBudgetGuard->permitsRun($input, $symfonyStyle)) {
                return ExitCode::BudgetAborted->value;
            }

            $this->beginAuditRun($symfonyStyle, $auditCommandInput);

            $report = $this->runAuditUseCase->execute($projectPath, $scanPaths, $auditCommandInput->noCache, $auditCommandInput->since, $this->acceptedFingerprintsFor($auditCommandInput));
            $report = $this->findingTypeFilter->apply($report);

            if (null !== $auditCommandInput->generateBaseline) {
                return $this->generateBaseline($symfonyStyle, $auditCommandInput, $report, $auditCommandInput->generateBaseline);
            }

            return $this->finalizeAuditRun($symfonyStyle, $auditCommandInput, $report);
        } catch (AuditAbortedByBudgetException $auditAbortedByBudgetException) {
            return $this->handleBudgetAbort($symfonyStyle, $auditCommandInput, $auditAbortedByBudgetException);
        } catch (Throwable $throwable) {
            $this->auditPresenter->error($symfonyStyle, $throwable);

            return ExitCode::Failure->value;
        }
    }

    /**
     * @param list<string> $scanPaths
     */
    private function showScannedFiles(SymfonyStyle $symfonyStyle, string $projectPath, array $scanPaths): void
    {
        $this->auditPresenter->scannedFiles(
            $symfonyStyle,
            $this->listScannedFilesUseCase->execute($projectPath, $scanPaths),
        );
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws UnsupportedOutputFormatException
     */
    private function runDryRun(
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        string $projectPath,
        array $scanPaths,
    ): int {
        $this->auditPresenter->estimatingSection($symfonyStyle);
        $auditReport = $this->estimateAuditCostUseCase->execute($projectPath, $scanPaths);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $auditReport);

        if ($auditCommandInput->isMachineReadableFormat()) {
            $this->reportWriter->write($auditReport, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);
        }

        if (!$auditCommandInput->isMachineReadableToStdout()) {
            $this->auditPresenter->dryRunResult($symfonyStyle, $auditReport);

            if (!$auditCommandInput->showScanned) {
                $this->auditPresenter->scannedFilesHint($symfonyStyle, $auditReport->filesScanned());
            }
        }

        return ExitCode::Success->value;
    }

    private function beginAuditRun(SymfonyStyle $symfonyStyle, AuditCommandInput $auditCommandInput): void
    {
        $this->auditPresenter->runningSection($symfonyStyle);

        if ($auditCommandInput->isMachineReadableToStdout()) {
            return;
        }

        $this->auditPresenter->longRunNotice($symfonyStyle);
        $this->progressReporterHolder->setDelegate(
            $symfonyStyle->isDecorated()
                ? new ConsoleProgressReporter($symfonyStyle)
                : new PlainProgressReporter($symfonyStyle),
        );
    }

    /**
     * Baseline fingerprints threaded into the pipeline so accepted findings
     * skip the reviewer. Empty while (re)generating a baseline — every
     * finding must then be collected, not suppressed.
     *
     * @return list<string>
     */
    private function acceptedFingerprintsFor(AuditCommandInput $auditCommandInput): array
    {
        if (null !== $auditCommandInput->generateBaseline) {
            return [];
        }

        return $this->baselineProcessor->acceptedFingerprints($auditCommandInput->baseline);
    }

    /**
     * @throws UnsupportedOutputFormatException
     */
    private function generateBaseline(
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        AuditReport $auditReport,
        string $generateBaseline,
    ): int {
        $fingerprintCount = $this->baselineProcessor->generate($auditReport, $generateBaseline);
        $this->reportWriter->write($auditReport, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);

        if (!$auditCommandInput->isMachineReadableToStdout()) {
            $this->auditPresenter->baselineGenerated($symfonyStyle, $generateBaseline, $fingerprintCount);
        }

        return ExitCode::Success->value;
    }

    /**
     * @throws UnsupportedOutputFormatException
     */
    private function finalizeAuditRun(
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        AuditReport $auditReport,
    ): int {
        $baselineResult = $this->baselineProcessor->apply($auditReport, $auditCommandInput->baseline);

        $reportToRender = OutputFormat::Sarif === $auditCommandInput->format ? $auditReport : $baselineResult->report;
        $this->reportWriter->write($reportToRender, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle, $baselineResult->acceptedFingerprints);

        $exitCode = $this->auditExitCodeResolver->resolve($baselineResult->report, $auditCommandInput->failOn ?? $this->riskLevel);

        if (!$auditCommandInput->isMachineReadableToStdout()) {
            $this->auditPresenter->result($symfonyStyle, $baselineResult->report, $exitCode);
        }

        return $exitCode;
    }

    /**
     * @throws UnsupportedOutputFormatException
     */
    private function handleBudgetAbort(
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        AuditAbortedByBudgetException $auditAbortedByBudgetException,
    ): int {
        $this->reportWriter->write(
            $auditAbortedByBudgetException->partialReport(),
            $auditCommandInput->format,
            $auditCommandInput->output,
            $symfonyStyle,
        );
        $this->auditPresenter->error($symfonyStyle, $auditAbortedByBudgetException);

        return ExitCode::BudgetAborted->value;
    }
}
