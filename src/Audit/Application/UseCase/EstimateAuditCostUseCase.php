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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScopedScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerSkillPromptRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CandidateFindingSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

/**
 * Estimates the tokens and cost of an audit from its scan alone, without
 * calling the LLM platform. Returns the estimate as the report's `AuditCost`.
 *
 * The attacker input of an iteration is the scanned content, each chunk's
 * system prompt and the project mapping, raised by `toolRoundTripRatio` when
 * `audit.tools_enabled` is on. The reviewer input is `reviewerInputRatio` of
 * the file content alone, counted `max_iterations` times, plus each file the
 * static candidates are reviewed against, counted once. Each output is
 * `outputRatio` of its input.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class EstimateAuditCostUseCase
{
    /** Conservative output:input ratio observed across reference audits. */
    public const float DEFAULT_OUTPUT_RATIO = 0.15;

    /**
     * Share of the file content the reviewer prompt carries, calibrated
     * against reference audits.
     */
    public const float DEFAULT_REVIEWER_INPUT_RATIO = 0.20;

    /**
     * Extra attacker input the tool-call rounds re-send when
     * `audit.tools_enabled` is on, calibrated against reference audits at
     * {@see CALIBRATION_MAX_TOOL_ITERATIONS} rounds.
     */
    public const float DEFAULT_TOOL_ROUND_TRIP_RATIO = 0.50;

    /**
     * The `audit.max_tool_iterations` bound the ratio above was measured at.
     * It moves only when the calibration is redone, never with
     * `AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS`.
     */
    public const int CALIBRATION_MAX_TOOL_ITERATIONS = 8;

    public function __construct(
        private ProjectFileScannerInterface $projectFileScanner,
        private TokenEstimatorInterface $tokenEstimator,
        private CostCalculator $costCalculator,
        private LoggerInterface $logger,
        private FileChunker $fileChunker,
        private AttackerSkillPromptRendererInterface $attackerSkillPromptRenderer,
        private string $primaryModel = '',
        private int $maxIterations = 3,
        private float $outputRatio = self::DEFAULT_OUTPUT_RATIO,
        private string $reviewerModel = '',
        private float $reviewerInputRatio = self::DEFAULT_REVIEWER_INPUT_RATIO,
        private ?GitChangedFilesResolverInterface $gitChangedFilesResolver = null,
        private bool $emitAllSkills = true,
        private bool $toolsEnabled = true,
        private float $toolRoundTripRatio = self::DEFAULT_TOOL_ROUND_TRIP_RATIO,
        private int $maxToolIterations = AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS,
        private ?AttackerPromptBuilderInterface $attackerPromptBuilder = null,
        private ?StageInterface $mappingStage = null,
        private ?SinceClosurePreview $sinceClosurePreview = null,
        private ?CandidateFindingSourceInterface $candidateFindingSource = null,
    ) {}

    /**
     * @param list<string> $scanPaths    project-relative paths to scope the
     *                                   estimate to, empty for the configured
     *                                   scan surface
     * @param ?string      $diffSinceRef narrows the estimate to the files
     *                                   `audit:run --since` would audit against
     *                                   this git ref
     *
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function execute(string $projectPath, array $scanPaths = [], ?string $diffSinceRef = null): AuditReport
    {
        $this->logger->info('Estimating audit cost (dry-run)', ['project' => $projectPath, 'scan_paths' => $scanPaths]);

        $auditContext = AuditContext::forProject($projectPath, $scanPaths, diffSinceRef: $diffSinceRef);
        $auditContext->markAsCostEstimate();

        $scopedScanResult = ScopedScan::resolve($this->projectFileScanner, $projectPath, $scanPaths);
        $scannedFiles = $scopedScanResult->audited->files;
        $files = $scannedFiles;
        if (null !== $diffSinceRef && $this->gitChangedFilesResolver instanceof GitChangedFilesResolverInterface) {
            $files = $this->filterByGitDiff($projectPath, $diffSinceRef, $files);
            $files = $this->sinceClosurePreview?->auditedFiles($projectPath, $scanPaths, $diffSinceRef, $files, $scopedScanResult->mappingFiles) ?? $files;
        }

        $auditContext->setProjectFiles($files);
        $auditContext->setFilesDiscovered(\count($scannedFiles));

        $fileContentPerRoundInput = 0;
        foreach ($files as $file) {
            $fileContentPerRoundInput += $this->tokenEstimator->estimateTokens($file->content(), $this->primaryModel);
        }

        $chunks = $this->fileChunker->chunk($files);
        $attackerPerRoundInput = $fileContentPerRoundInput + $this->systemPromptTokens($chunks) + (\count($chunks) * $this->mappingPromptTokens($projectPath, $scanPaths, $scopedScanResult->mappingFiles));

        if ($this->toolsEnabled) {
            $attackerPerRoundInput = $this->tokenCount($attackerPerRoundInput * $this->toolRoundTripMultiplier());
        }

        $attackerInputTokens = $this->tokenCount($attackerPerRoundInput * $this->maxIterations);
        $attackerOutputTokens = (int) ceil($attackerInputTokens * $this->outputRatio);
        $attackerCostUsd = $this->costCalculator->costForCall($attackerInputTokens, $attackerOutputTokens, $this->primaryModel);

        $reviewerModel = '' === $this->reviewerModel ? $this->primaryModel : $this->reviewerModel;
        $reviewerInputTokens = $this->tokenCount($fileContentPerRoundInput * $this->maxIterations * $this->reviewerInputRatio + $this->staticCandidateReviewTokens($files, $reviewerModel));
        $reviewerOutputTokens = (int) ceil($reviewerInputTokens * $this->outputRatio);
        $reviewerCostUsd = $this->costCalculator->costForCall($reviewerInputTokens, $reviewerOutputTokens, $reviewerModel);

        $estimatedInputTokens = $this->tokenCount($attackerInputTokens + $reviewerInputTokens);
        $estimatedOutputTokens = $attackerOutputTokens + $reviewerOutputTokens;
        $estimatedCostUsd = $attackerCostUsd + $reviewerCostUsd;

        $byRole = [
            AgentRole::Attacker->value => [
                'model' => $this->primaryModel,
                'input_tokens' => $attackerInputTokens,
                'output_tokens' => $attackerOutputTokens,
                'estimated_cost_usd' => round($attackerCostUsd, 6),
            ],
            AgentRole::Reviewer->value => [
                'model' => $reviewerModel,
                'input_tokens' => $reviewerInputTokens,
                'output_tokens' => $reviewerOutputTokens,
                'estimated_cost_usd' => round($reviewerCostUsd, 6),
            ],
        ];

        $auditCost = AuditCost::of($estimatedInputTokens, $estimatedOutputTokens, $estimatedCostUsd, $this->primaryModel, $byRole);

        $this->logger->info('Dry-run estimate ready', [
            'files' => \count($files),
            'input_tokens' => $estimatedInputTokens,
            'output_tokens' => $estimatedOutputTokens,
            'estimated_cost_usd' => $estimatedCostUsd,
            'attacker_cost_usd' => $attackerCostUsd,
            'reviewer_cost_usd' => $reviewerCostUsd,
        ]);

        return AuditReport::fromContext($auditContext, $auditCost);
    }

    /**
     * Counts the files the reviewer is sent with the static candidates: each
     * file once per review call of its candidates, which holds at most
     * {@see ReviewerAgent::MAX_FILE_GROUP_SIZE} of them.
     *
     * @param list<ProjectFile> $files
     */
    private function staticCandidateReviewTokens(array $files, string $reviewerModel): int
    {
        if (!$this->candidateFindingSource instanceof CandidateFindingSourceInterface) {
            return 0;
        }

        $filesByPath = [];
        foreach ($files as $file) {
            $filesByPath[$file->relativePath()] = $file;
        }

        $candidatesByPath = array_count_values(array_map(
            static fn (Vulnerability $vulnerability): string => $vulnerability->filePath(),
            $this->candidateFindingSource->candidatesIn($files),
        ));

        $tokens = 0;
        foreach ($candidatesByPath as $path => $candidates) {
            $reviewCalls = (int) ceil($candidates / ReviewerAgent::MAX_FILE_GROUP_SIZE);
            $tokens += $reviewCalls * $this->tokenEstimator->estimateTokens(($filesByPath[$path] ?? null)?->content() ?? '', $reviewerModel);
        }

        return $tokens;
    }

    /**
     * Rounds up, holding a count past the largest integer at `PHP_INT_MAX`.
     */
    private function tokenCount(int|float $tokens): int
    {
        if (\is_int($tokens)) {
            return $tokens;
        }

        return $tokens < \PHP_INT_MAX ? (int) ceil($tokens) : \PHP_INT_MAX;
    }

    /**
     * Scales the calibrated ratio by `audit.max_tool_iterations`, so lowering
     * that bound lowers the estimate.
     */
    private function toolRoundTripMultiplier(): float
    {
        return 1.0 + $this->toolRoundTripRatio * ($this->maxToolIterations / self::CALIBRATION_MAX_TOOL_ITERATIONS);
    }

    /**
     * Counts each chunk's system prompt as a run builds it, or its skill blocks
     * alone without a prompt builder.
     *
     * @param list<list<ProjectFile>> $chunks
     */
    private function systemPromptTokens(array $chunks): int
    {
        $total = 0;
        foreach ($chunks as $chunk) {
            $total += $this->attackerPromptBuilder instanceof AttackerPromptBuilderInterface
                ? $this->tokenEstimator->estimateTokens($this->attackerPromptBuilder->buildSystemPrompt($chunk), $this->primaryModel)
                : $this->skillPromptTokens($chunk);
        }

        return $total;
    }

    /**
     * Counts the project mapping every chunk's user message carries, mapped as
     * the pipeline maps it: from every scanned file whatever `--since` keeps,
     * plus the configured scope under `--path`.
     *
     * @param list<string>      $scanPaths
     * @param list<ProjectFile> $mappingFiles
     *
     * @throws InvalidAuditContextException
     */
    private function mappingPromptTokens(string $projectPath, array $scanPaths, array $mappingFiles): int
    {
        if (!$this->attackerPromptBuilder instanceof AttackerPromptBuilderInterface || !$this->mappingStage instanceof StageInterface) {
            return 0;
        }

        $auditContext = AuditContext::forProject($projectPath, $scanPaths);
        $auditContext->setMappingFiles($mappingFiles);

        $this->mappingStage->process($auditContext);
        $symfonyMapping = $auditContext->mapping();

        return $symfonyMapping instanceof SymfonyMapping
            ? $this->tokenEstimator->estimateTokens($this->attackerPromptBuilder->buildUserMessage([], $symfonyMapping), $this->primaryModel)
            : 0;
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function skillPromptTokens(array $files): int
    {
        $presentTypes = array_map(
            static fn (ProjectFile $projectFile): ProjectFileType => $projectFile->fileType(),
            $files,
        );

        $skillPrompt = $this->attackerSkillPromptRenderer->render($presentTypes, $this->emitAllSkills);

        return '' === $skillPrompt ? 0 : $this->tokenEstimator->estimateTokens($skillPrompt, $this->primaryModel);
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    private function filterByGitDiff(string $projectPath, string $ref, array $files): array
    {
        $changed = $this->gitChangedFilesResolver?->changedSince($projectPath, $ref) ?? [];
        $changedSet = array_flip($changed);

        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => \array_key_exists($projectFile->relativePath(), $changedSet),
        ));
    }
}
