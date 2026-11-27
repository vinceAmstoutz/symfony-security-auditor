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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedExceptionInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelNotice;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ConsoleProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\PlainProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\BaselineWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\RunRefusedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ScanPathOutsideProjectException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeReportWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsupportedOutputFormatException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\WorkingDirectoryUnavailableException;

#[AsCommand(
    name: self::NAME,
    description: self::DESCRIPTION,
    aliases: [self::ALIAS],
    help: AuditCommandHelp::HELP,
)]
/** @internal not part of the BC promise: the command *name* (`audit:run`), its `audit` alias and the CLI surface are public, but the PHP class itself is for internal use only. */
final readonly class AuditCommand
{
    public const string NAME = 'audit:run';

    public const string ALIAS = 'audit';

    private const string OUTPUT_FILE_LACKING_A_FORMAT = 'The output file "%s" has no extension to pick the report format from, so it gets the console report. Such a name is deprecated and will be refused in 2.0: give it an extension (.html, .json, .sarif, .md or .xml) or choose the format with --format.';

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
        private AuditedProjectPathHolder $auditedProjectPathHolder,
        private BaselineProcessorInterface $baselineProcessor,
        private UnpricedModelBudgetGuardInterface $unpricedModelBudgetGuard,
        private ReviewerFeedbackHolder $reviewerFeedbackHolder,
        private bool $secretScrubbingEnabled,
        private FindingTypeFilterInterface $findingTypeFilter,
        private array $configNotices = [],
        private RiskLevel $riskLevel = RiskLevel::Critical,
        private bool $pocSynthesisEnabled = false,
        private bool $fixSynthesisEnabled = false,
        private AuditCommandDefaults $auditCommandDefaults = new AuditCommandDefaults(),
        private BaselineFilePathsHolder $baselineFilePathsHolder = new BaselineFilePathsHolder(),
        private ?PulledModelNotice $pulledModelNotice = null,
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
        $auditCommandInput->applyDefaults($this->auditCommandDefaults);

        $auditTarget = AuditTarget::named($auditCommandInput->resolvedProjectPath(), $auditCommandInput->scanPaths(), $this->holdsScanFiles(...));
        $projectPath = $auditTarget->projectPath;
        $this->auditedProjectPathHolder->set($projectPath);

        $displayStyle = $this->displayStyle($symfonyStyle, $auditCommandInput);
        $this->auditPresenter->header($displayStyle, $projectPath);

        try {
            $this->assertProjectIsDirectory($projectPath);
            $scanPaths = ScanPathResolver::resolve($auditTarget->scanPaths, $projectPath);
        } catch (InvalidAuditContextException|ScanPathOutsideProjectException $exception) {
            $this->auditPresenter->error($displayStyle, $exception);

            return ExitCode::Failure->value;
        }

        if (null !== $auditTarget->folder) {
            $this->auditPresenter->enclosingProject($displayStyle, $auditTarget->folder, $scanPaths);
        }

        $this->auditPresenter->preflightWarnings($displayStyle, $this->secretScrubbingEnabled, $this->configNotices);
        $this->warnAboutMinScoreOutsideRange($displayStyle, $auditCommandInput);

        return $this->runAuditFlow($input, $symfonyStyle, $auditCommandInput, $projectPath, $scanPaths);
    }

    /**
     * @throws InvalidAuditContextException
     */
    private function holdsScanFiles(string $directory): bool
    {
        return $this->listScannedFilesUseCase->holdsAFile($directory);
    }

    private function warnAboutMinScoreOutsideRange(SymfonyStyle $symfonyStyle, AuditCommandInput $auditCommandInput): void
    {
        $belowRange = $auditCommandInput->minScoreBelowRange();
        if (null !== $belowRange) {
            $this->auditPresenter->minScoreBelowRange($symfonyStyle, $belowRange);
        }

        $aboveRange = $auditCommandInput->minScoreAboveRange();
        if (null !== $aboveRange) {
            $this->auditPresenter->minScoreAboveRange($symfonyStyle, $aboveRange);
        }
    }

    /**
     * @throws InvalidAuditContextException
     */
    private function assertProjectIsDirectory(string $projectPath): void
    {
        if (!is_dir($projectPath)) {
            throw InvalidAuditContextException::forInvalidProjectPath($projectPath);
        }
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws UnsupportedOutputFormatException
     * @throws WorkingDirectoryUnavailableException
     */
    private function runAuditFlow(
        InputInterface $input,
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        string $projectPath,
        array $scanPaths,
    ): int {
        $displayStyle = $this->displayStyle($symfonyStyle, $auditCommandInput);

        try {
            try {
                $auditCommandInput->assertNoConflictingOptions();
                $this->warnOfAnOutputFileLackingAFormat($symfonyStyle, $auditCommandInput);
                $this->assertOutputsWritable($auditCommandInput, $projectPath);

                if ($auditCommandInput->showScanned) {
                    $this->showScannedFiles($displayStyle, $projectPath, $scanPaths, $auditCommandInput->since);
                }

                if ($auditCommandInput->dryRun) {
                    return $this->runDryRun([$symfonyStyle, $displayStyle], $auditCommandInput, $projectPath, $scanPaths);
                }

                if ($auditCommandInput->showScanned) {
                    return ExitCode::Success->value;
                }

                $refusedStart = $this->refusedStart($input, $symfonyStyle);
                if ($refusedStart instanceof ExitCode) {
                    return $refusedStart->value;
                }

                $this->auditPresenter->preflightWarnings($displayStyle, true, $this->pulledModelNotice?->notices() ?? []);
                $this->beginAuditRun($symfonyStyle, $auditCommandInput);

                $this->reviewerFeedbackHolder->set($this->baselineProcessor->feedback($auditCommandInput->baseline));
                $this->baselineFilePathsHolder->set($projectPath, $this->baselineProcessor->filePaths($auditCommandInput->baseline));

                $report = $this->runAuditUseCase->execute($projectPath, $scanPaths, $auditCommandInput->noCache, $auditCommandInput->since, $this->acceptedFingerprintsFor($auditCommandInput));
                $report = $this->findingTypeFilter->apply($report);

                if (null !== $auditCommandInput->generateBaseline) {
                    return $this->generateBaseline($symfonyStyle, $auditCommandInput, $report, $auditCommandInput->generateBaseline);
                }

                return $this->finalizeAuditRun($symfonyStyle, $auditCommandInput, $report);
            } catch (AuditAbortedExceptionInterface $auditAbortedException) {
                return $this->handleAbort($symfonyStyle, $auditCommandInput, $auditAbortedException);
            }
        } catch (Throwable $throwable) {
            $this->auditPresenter->error($displayStyle, $throwable);

            return ExitCode::Failure->value;
        }
    }

    private function warnOfAnOutputFileLackingAFormat(SymfonyStyle $symfonyStyle, AuditCommandInput $auditCommandInput): void
    {
        $outputFileLackingAFormat = $auditCommandInput->outputFileLackingAFormat();
        if (null !== $outputFileLackingAFormat) {
            $symfonyStyle->getErrorStyle()->warning(\sprintf(self::OUTPUT_FILE_LACKING_A_FORMAT, $outputFileLackingAFormat));
        }
    }

    /**
     * Returns how a run the guard refuses to start exits: `2` for a budget it
     * cannot enforce, `1` for any other refusal. Null when the run may start.
     */
    private function refusedStart(InputInterface $input, SymfonyStyle $symfonyStyle): ?ExitCode
    {
        try {
            return $this->unpricedModelBudgetGuard->permitsRun($input, $symfonyStyle) ? null : ExitCode::BudgetAborted;
        } catch (RunRefusedException $runRefusedException) {
            $symfonyStyle->getErrorStyle()->error($runRefusedException->getMessage());

            return ExitCode::Failure;
        }
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     * @throws UnsafeBaselineWriteException
     * @throws BaselineWriteFailedException
     */
    private function assertOutputsWritable(AuditCommandInput $auditCommandInput, string $projectPath): void
    {
        $this->reportWriter->assertWritable($auditCommandInput->reportFile(), $projectPath);

        if (null !== $auditCommandInput->generateBaseline) {
            $this->baselineProcessor->assertWritable($auditCommandInput->generateBaseline, $projectPath);
        }
    }

    private function displayStyle(SymfonyStyle $symfonyStyle, AuditCommandInput $auditCommandInput): SymfonyStyle
    {
        return $auditCommandInput->isMachineReadableToStdout() ? $symfonyStyle->getErrorStyle() : $symfonyStyle;
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     */
    private function showScannedFiles(SymfonyStyle $symfonyStyle, string $projectPath, array $scanPaths, ?string $since): void
    {
        $projectFiles = $this->listScannedFilesUseCase->execute($projectPath, $scanPaths, $since);

        if ([] === $projectFiles) {
            $this->auditPresenter->noFilesMatched($symfonyStyle, $projectPath, $scanPaths);

            return;
        }

        $this->auditPresenter->scannedFiles($symfonyStyle, $projectFiles);
    }

    /**
     * @param array{SymfonyStyle, SymfonyStyle} $styles    stdout style and human-display style
     * @param list<string>                      $scanPaths
     *
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    private function runDryRun(
        array $styles,
        AuditCommandInput $auditCommandInput,
        string $projectPath,
        array $scanPaths,
    ): int {
        [$symfonyStyle, $displayStyle] = $styles;
        $this->auditPresenter->estimatingSection($displayStyle);
        $auditReport = $this->estimateAuditCostUseCase->execute($projectPath, $scanPaths, $auditCommandInput->since);

        $this->auditPresenter->unsupportedModelWarnings($displayStyle, $auditReport);
        $this->auditPresenter->synthesisCostWarnings($displayStyle, $this->pocSynthesisEnabled, $this->fixSynthesisEnabled);

        if ($auditCommandInput->isMachineReadableFormat() || null !== $auditCommandInput->output) {
            $this->reportWriter->write($auditReport, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);
        }

        if (!$auditCommandInput->isMachineReadableToStdout()) {
            $this->auditPresenter->dryRunResult($displayStyle, $auditReport);

            if (!$auditCommandInput->showScanned) {
                $this->auditPresenter->scannedFilesHint($displayStyle, $auditReport->filesScanned());
            }
        }

        return ExitCode::Success->value;
    }

    private function beginAuditRun(SymfonyStyle $symfonyStyle, AuditCommandInput $auditCommandInput): void
    {
        $this->auditPresenter->runningSection($this->displayStyle($symfonyStyle, $auditCommandInput));

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
     * The fingerprints whose findings skip the reviewer: none while generating
     * a baseline, none for SARIF, which reports them as suppressed results.
     * Any other run reads the baseline, SARIF included, so a malformed entry
     * stops it before the first model call.
     *
     * @return list<string>
     */
    private function acceptedFingerprintsFor(AuditCommandInput $auditCommandInput): array
    {
        if (null !== $auditCommandInput->generateBaseline) {
            return [];
        }

        $acceptedFingerprints = $this->baselineProcessor->acceptedFingerprints($auditCommandInput->baseline);

        return OutputFormat::Sarif === $auditCommandInput->format ? [] : $acceptedFingerprints;
    }

    /**
     * Writes the report whatever becomes of the baseline. A run with no verdict
     * writes no baseline and fails.
     *
     * @throws UnsupportedOutputFormatException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    private function generateBaseline(
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        AuditReport $auditReport,
        string $generateBaseline,
    ): int {
        if ($this->auditExitCodeResolver->hasNoVerdict($auditReport)) {
            $this->reportWriter->write($auditReport, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);
            $this->auditPresenter->baselineKept($this->displayStyle($symfonyStyle, $auditCommandInput), $generateBaseline, $auditReport);

            return ExitCode::Failure->value;
        }

        try {
            $fingerprintCount = $this->baselineProcessor->generate($auditReport, $generateBaseline);
        } finally {
            $this->reportWriter->write($auditReport, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);
        }

        $exitCode = $auditCommandInput->failsOnIncomplete() && !$auditReport->isComplete() ? ExitCode::Incomplete->value : ExitCode::Success->value;

        if (!$auditCommandInput->isMachineReadableToStdout()) {
            $this->auditPresenter->baselineGenerated($symfonyStyle, $generateBaseline, $fingerprintCount);
        }

        $this->auditPresenter->incompleteRunNotice($this->displayStyle($symfonyStyle, $auditCommandInput), $auditReport, $exitCode, $auditCommandInput->failOnIncompleteSetting());

        return $exitCode;
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    private function finalizeAuditRun(
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        AuditReport $auditReport,
    ): int {
        $baselineResult = $this->baselineProcessor->apply($auditReport, $auditCommandInput->baseline);

        $reportToRender = OutputFormat::Sarif === $auditCommandInput->format ? $auditReport : $baselineResult->report;
        $this->reportWriter->write($reportToRender, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle, $baselineResult->acceptedFingerprints);

        $exitCode = $this->auditExitCodeResolver->resolve(
            $baselineResult->report,
            $auditCommandInput->failOn ?? $this->riskLevel,
            $auditCommandInput->minScore,
            $auditCommandInput->failsOnIncomplete(),
        );

        if ($auditCommandInput->isMachineReadableToStdout()) {
            $this->auditPresenter->incompleteRunNotice($this->displayStyle($symfonyStyle, $auditCommandInput), $baselineResult->report, $exitCode, $auditCommandInput->failOnIncompleteSetting());

            return $exitCode;
        }

        $this->auditPresenter->result($symfonyStyle, $baselineResult->report, $exitCode, $auditCommandInput->failOnIncompleteSetting());

        return $exitCode;
    }

    /**
     * Writes the partial report. One that cannot be saved is reported and the
     * abort keeps its exit code.
     *
     * @throws UnsupportedOutputFormatException
     */
    private function handleAbort(
        SymfonyStyle $symfonyStyle,
        AuditCommandInput $auditCommandInput,
        AuditAbortedExceptionInterface $auditAbortedException,
    ): int {
        $auditReport = $this->findingTypeFilter->apply($auditAbortedException->partialReport());
        $baselineResult = $this->baselineProcessor->apply($auditReport, $auditCommandInput->baseline);
        $reportToWrite = OutputFormat::Sarif === $auditCommandInput->format ? $auditReport : $baselineResult->report;
        $displayStyle = $this->displayStyle($symfonyStyle, $auditCommandInput);

        try {
            $this->reportWriter->write(
                $reportToWrite,
                $auditCommandInput->format,
                $auditCommandInput->output,
                $symfonyStyle,
                $baselineResult->acceptedFingerprints,
            );
        } catch (ReportWriteFailedException|UnsafeReportWriteException $reportWriteException) {
            $this->auditPresenter->error($displayStyle, $reportWriteException);
        }

        $this->auditPresenter->error($displayStyle, $auditAbortedException);

        return $auditAbortedException instanceof AuditAbortedByBudgetException ? ExitCode::BudgetAborted->value : ExitCode::Failure->value;
    }
}
