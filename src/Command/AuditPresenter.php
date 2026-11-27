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

use InvalidArgumentException;
use Override;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\WorkflowCommandText;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TerminalTextSanitizer;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class AuditPresenter implements AuditPresenterInterface
{
    private const string NO_FILE_FOUND_VERDICT = 'The scan found no file to audit, so the run has no verdict.';

    public function __construct(
        private PricingProviderInterface $pricingProvider,
        private ConsoleBannerInterface $consoleBanner = new ConsoleBanner(),
        private WorkflowCommandNeutralizerInterface $workflowCommandNeutralizer = new WorkflowCommandNeutralizer(false),
        private ?string $cliAgent = null,
    ) {}

    #[Override]
    public function header(SymfonyStyle $symfonyStyle, string $projectPath): void
    {
        $this->consoleBanner->render($symfonyStyle);

        $symfonyStyle->text([
            \sprintf('Project: <info>%s</info>', OutputFormatter::escape($projectPath)),
            'Pipeline: Ingestion -> Mapping -> Audit (Attacker vs Reviewer)',
            '',
        ]);
    }

    #[Override]
    public function enclosingProject(SymfonyStyle $symfonyStyle, string $folder, array $scanPaths): void
    {
        $symfonyStyle->text(EnclosingProjectScope::line(
            OutputFormatter::escape($this->sanitizeForWarning($folder)),
            array_map($this->sanitizePathForListing(...), $scanPaths),
        ));
    }

    #[Override]
    public function preflightWarnings(SymfonyStyle $symfonyStyle, bool $secretScrubbingEnabled, array $configNotices = []): void
    {
        foreach ($configNotices as $configNotice) {
            $symfonyStyle->getErrorStyle()->note($configNotice);
        }

        if ($secretScrubbingEnabled) {
            return;
        }

        $symfonyStyle->getErrorStyle()->warning('Secret scrubbing is disabled. File contents will be sent verbatim to the configured LLM provider. If that provider runs in the cloud, credentials in committed configs or .env.dist files may be exposed. Re-enable scan.secret_scrubbing.enabled (the default) or confirm you are using a local provider.');
    }

    #[Override]
    public function minScoreBelowRange(SymfonyStyle $symfonyStyle, int $minScore): void
    {
        $symfonyStyle->getErrorStyle()->warning(\sprintf('--min-score %d is below 0, the lowest normalized score, so it never fails a run. Use a value from 0 to 100.', $minScore));
    }

    #[Override]
    public function minScoreAboveRange(SymfonyStyle $symfonyStyle, int $minScore): void
    {
        $symfonyStyle->getErrorStyle()->warning(\sprintf('--min-score %d is above 100, the highest normalized score, so it fails every run. Use a value from 0 to 100.', $minScore));
    }

    #[Override]
    public function unsupportedModelWarnings(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void
    {
        $unsupportedModels = $this->unsupportedModels($auditReport->cost());

        if ([] === $unsupportedModels || null !== $this->cliAgent) {
            return;
        }

        $symfonyStyle->getErrorStyle()->warning(UnpricedModelNotice::forEstimate($unsupportedModels));
    }

    #[Override]
    public function synthesisCostWarnings(SymfonyStyle $symfonyStyle, bool $pocSynthesisEnabled, bool $fixSynthesisEnabled): void
    {
        if ($pocSynthesisEnabled && $fixSynthesisEnabled) {
            $symfonyStyle->getErrorStyle()->warning('PoC synthesis (audit.poc_synthesis.enabled) and fix synthesis (audit.fix_synthesis.enabled) are both enabled. Their LLM calls are not included in this cost estimate, so a real run will cost more than the figure shown.');

            return;
        }

        if ($pocSynthesisEnabled) {
            $symfonyStyle->getErrorStyle()->warning('PoC synthesis is enabled (audit.poc_synthesis.enabled). Its LLM calls are not included in this cost estimate, so a real run will cost more than the figure shown.');
        }

        if ($fixSynthesisEnabled) {
            $symfonyStyle->getErrorStyle()->warning('Fix synthesis is enabled (audit.fix_synthesis.enabled). Its LLM calls are not included in this cost estimate, so a real run will cost more than the figure shown.');
        }
    }

    /** @return array<string, string> */
    private function unsupportedModels(AuditCost $auditCost): array
    {
        $unsupportedModels = [];
        foreach ($auditCost->byRole() as $entry) {
            $model = $entry['model'];
            if (!$this->pricingProvider->hasModel($model)) {
                $unsupportedModels[$model] = $model;
            }
        }

        return $unsupportedModels;
    }

    #[Override]
    public function runningSection(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->section('Running audit pipeline...');
    }

    #[Override]
    public function longRunNotice(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->comment('An audit takes minutes, 20+ on large projects. Progress streams below.');
    }

    #[Override]
    public function estimatingSection(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->section(null === $this->cliAgent ? 'Estimating audit cost (dry run)...' : 'Estimating audit size (dry run)...');
    }

    #[Override]
    public function dryRunResult(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void
    {
        (new DryRunEstimate(null !== $this->cliAgent))->render($symfonyStyle, $auditReport->cost());
        $this->lightConfirmation($symfonyStyle, 'Dry run complete.');
    }

    #[Override]
    public function noFilesMatched(SymfonyStyle $symfonyStyle, string $projectPath, array $scanPaths): void
    {
        $project = $this->sanitizeForWarning($projectPath);

        if ([] === $scanPaths) {
            $symfonyStyle->warning(\sprintf('No files matched under "%s". Check your included_paths configuration.', $project));

            return;
        }

        $symfonyStyle->warning(\sprintf(
            'No files matched under "%s" for --path %s. Check that each --path exists in the project, relative to its root, and holds PHP, Twig, YAML or XML files.',
            $project,
            implode(', ', array_map($this->sanitizeForWarning(...), $scanPaths)),
        ));
    }

    #[Override]
    public function scannedFiles(SymfonyStyle $symfonyStyle, array $projectFiles): void
    {
        $symfonyStyle->section(\sprintf('Scanned files (%d)', \count($projectFiles)));

        foreach ($this->relativePathsByType($projectFiles) as $type => $relativePaths) {
            $symfonyStyle->writeln(\sprintf(' <info>%s</info> (%d)', $this->bucketLabel($type), \count($relativePaths)));
            $symfonyStyle->listing(array_map($this->sanitizePathForListing(...), $relativePaths));
        }

        $this->lightConfirmation($symfonyStyle, \sprintf('%d file(s) in scope.', \count($projectFiles)));
    }

    private function lightConfirmation(SymfonyStyle $symfonyStyle, string $message): void
    {
        $symfonyStyle->writeln(\sprintf($symfonyStyle->isDecorated() ? '  ✅ %s' : '  %s', $message));
        $symfonyStyle->newLine();
    }

    #[Override]
    public function scannedFilesHint(SymfonyStyle $symfonyStyle, int $fileCount): void
    {
        $symfonyStyle->comment(\sprintf('Tip: run with --show-scanned to list the %d file(s) that would be audited.', $fileCount));
    }

    /**
     * `SymfonyStyle::warning()` escapes console markup itself.
     */
    private function sanitizeForWarning(string $text): string
    {
        return WorkflowCommandText::inLine(TerminalTextSanitizer::collapseToSingleLine(mb_scrub($text, 'UTF-8')));
    }

    private function sanitizePathForListing(string $relativePath): string
    {
        return OutputFormatter::escape(WorkflowCommandText::inLine(TerminalTextSanitizer::collapseToSingleLine(mb_scrub($relativePath, 'UTF-8'))));
    }

    /**
     * @param list<ProjectFile> $projectFiles
     *
     * @return array<string, list<string>>
     */
    private function relativePathsByType(array $projectFiles): array
    {
        $byType = [];
        foreach ($projectFiles as $projectFile) {
            $byType[$projectFile->type()][] = $projectFile->relativePath();
        }

        return $this->withUncategorizedBucketsLast($byType);
    }

    /**
     * @param array<string, list<string>> $byType
     *
     * @return array<string, list<string>>
     */
    private function withUncategorizedBucketsLast(array $byType): array
    {
        $trailing = [];
        foreach ([ProjectFileType::PHP->value, ProjectFileType::OTHER->value] as $trailingType) {
            if (\array_key_exists($trailingType, $byType)) {
                $trailing[$trailingType] = $byType[$trailingType];
                unset($byType[$trailingType]);
            }
        }

        return $byType + $trailing;
    }

    private function bucketLabel(string $type): string
    {
        return match ($type) {
            ProjectFileType::PHP->value => 'php · uncategorized',
            ProjectFileType::OTHER->value => 'other · uncategorized',
            default => $type,
        };
    }

    #[Override]
    public function error(SymfonyStyle $symfonyStyle, Throwable $throwable): void
    {
        $message = $throwable instanceof InvalidArgumentException
            ? $throwable->getMessage()
            : \sprintf('Unexpected error: %s', $throwable->getMessage());

        $symfonyStyle->error($this->workflowCommandNeutralizer->message($message));
    }

    #[Override]
    public function result(SymfonyStyle $symfonyStyle, AuditReport $auditReport, int $exitCode, string $failOnIncompleteSetting): void
    {
        if (Command::FAILURE === $exitCode && !$auditReport->isWithoutVerdict()) {
            $totalVulnerabilities = $auditReport->totalVulnerabilities();
            $symfonyStyle->caution(\sprintf(
                'Audit failed a configured gate. Risk: %s. Score: %d/100. %d %s found.',
                $auditReport->riskLevel(),
                $auditReport->normalizedScore(),
                $totalVulnerabilities,
                1 === $totalVulnerabilities ? 'vulnerability' : 'vulnerabilities',
            ));
            $this->incompleteRunNotice($symfonyStyle, $auditReport, $exitCode, $failOnIncompleteSetting);

            return;
        }

        if ($this->statesNoCleanResult($auditReport)) {
            $this->incompleteRunNotice($symfonyStyle, $auditReport, $exitCode, $failOnIncompleteSetting);

            return;
        }

        $symfonyStyle->success(\sprintf(
            'Audit complete. Risk: %s | Vulnerabilities: %d',
            $auditReport->riskLevel(),
            $auditReport->totalVulnerabilities(),
        ));
    }

    #[Override]
    public function incompleteRunNotice(SymfonyStyle $symfonyStyle, AuditReport $auditReport, int $exitCode, string $failOnIncompleteSetting): void
    {
        if (!$this->statesNoCleanResult($auditReport)) {
            return;
        }

        $summary = $this->incompleteSummary($auditReport);

        if (ExitCode::Incomplete->value === $exitCode) {
            $symfonyStyle->error(\sprintf('%s The run fails because %s is set.', $summary, $failOnIncompleteSetting));

            return;
        }

        if (ExitCode::Failure->value === $exitCode && $auditReport->isWithoutVerdict()) {
            $symfonyStyle->error(\sprintf('%s A run with no verdict cannot pass, so it fails.', $summary));

            return;
        }

        $symfonyStyle->warning(ExitCode::Success->value === $exitCode ? \sprintf('%s Pass --fail-on-incomplete to fail the run when this happens.', $summary) : $summary);
    }

    private function statesNoCleanResult(AuditReport $auditReport): bool
    {
        return !$auditReport->isComplete() || $auditReport->isWithoutVerdict();
    }

    /**
     * States no risk level for a run with no verdict.
     */
    private function incompleteSummary(AuditReport $auditReport): string
    {
        if (0 === $auditReport->filesDiscovered()) {
            return self::NO_FILE_FOUND_VERDICT;
        }

        if ($auditReport->hasNoVerdict()) {
            return \sprintf(
                'Audit incomplete: none of the %d file(s) in scope could be analyzed, so the run has no verdict. Vulnerabilities: %d.',
                $auditReport->filesScanned(),
                $auditReport->totalVulnerabilities(),
            );
        }

        return \sprintf(
            'Audit incomplete: %d file(s) could not be fully analyzed, so the absence of findings there proves nothing. Risk: %s | Vulnerabilities: %d.',
            \count($auditReport->unanalyzedFiles()),
            $auditReport->riskLevel(),
            $auditReport->totalVulnerabilities(),
        );
    }

    #[Override]
    public function baselineKept(SymfonyStyle $symfonyStyle, string $path, AuditReport $auditReport): void
    {
        $symfonyStyle->error(\sprintf(
            '%s The baseline at %s was left as it was: a run with no verdict cannot replace the accepted findings, so it fails.',
            0 === $auditReport->filesDiscovered()
                ? self::NO_FILE_FOUND_VERDICT
                : \sprintf('Audit incomplete: none of the %d file(s) in scope could be analyzed, so the run has no verdict.', $auditReport->filesScanned()),
            $path,
        ));
    }

    #[Override]
    public function baselineGenerated(SymfonyStyle $symfonyStyle, string $path, int $fingerprintCount): void
    {
        $symfonyStyle->success(\sprintf(
            'Baseline written to %s with %d finding fingerprint(s). Future runs will suppress these unless you pass a different --baseline.',
            $path,
            $fingerprintCount,
        ));
    }
}
