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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerSkillPromptRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

/**
 * Walks the ingestion stage of the audit pipeline, estimates how many tokens
 * an actual run would consume, and returns an `AuditReport` carrying the
 * estimate as its `AuditCost`. Never invokes the LLM platform — `--dry-run`
 * stays free regardless of project size.
 *
 * Estimation strategy: every scanned file contributes its content to a
 * synthetic "attacker prompt" (input). The attacker system prompt's skill
 * blocks are sent once per chunk — chunked the same way `FileChunker` chunks
 * a real run — and added on top. When `audit.tools_enabled` is on, the
 * attacker may take several tool-call rounds per chunk, each resending the
 * growing conversation plus the tool schemas — `toolRoundTripRatio` inflates
 * the per-round input to account for that. Output tokens are projected at
 * `outputRatio * input` because audit prompts are heavily input-skewed.
 * Multiplied by `max_iterations` to account for the attacker/reviewer loop.
 *
 * `reviewerInputRatio` is applied to the file-content sum alone, never to the
 * attacker total: the reviewer prompt carries no skill blocks, so folding the
 * attacker's own overhead into its base would inflate the reviewer estimate by
 * an overhead it never sends.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EstimateAuditCostUseCase
{
    /** Conservative output:input ratio observed across reference audits. */
    public const float DEFAULT_OUTPUT_RATIO = 0.15;

    /**
     * Fraction of the attacker's per-iteration input that the reviewer
     * receives. The reviewer only sees filtered findings (not the full
     * file chunks), so its prompt is much smaller than the attacker's.
     * Calibrated against reference audits at ~20% of attacker input.
     */
    public const float DEFAULT_REVIEWER_INPUT_RATIO = 0.20;

    /**
     * Conservative estimate of the extra attacker input consumed by
     * tool-call round-trips (the re-sent conversation plus tool schemas on
     * every round) when `audit.tools_enabled` is on. Calibrated against
     * reference audits at ~50% on top of the base per-round input, with
     * `audit.max_tool_iterations` left at {@see CALIBRATION_MAX_TOOL_ITERATIONS}.
     */
    public const float DEFAULT_TOOL_ROUND_TRIP_RATIO = 0.50;

    /**
     * The `audit.max_tool_iterations` bound the ratio above was measured
     * against. It moves only when the calibration is redone, which is why it
     * is not simply `AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS` — changing
     * that default must change the estimate, not silently re-anchor it.
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
    ) {}

    /**
     * @param list<string> $scanPaths    optional project-relative subdirectories
     *                                   to restrict the estimate to; empty list
     *                                   (the default) estimates over the whole
     *                                   project
     * @param ?string      $diffSinceRef when set, mirrors `IngestionStage` by
     *                                   narrowing the estimate to files changed
     *                                   against this git ref, matching what an
     *                                   `audit:run --since` would actually scan
     *
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function execute(string $projectPath, array $scanPaths = [], ?string $diffSinceRef = null): AuditReport
    {
        $this->logger->info('Estimating audit cost (dry-run)', ['project' => $projectPath, 'scan_paths' => $scanPaths]);

        $auditContext = AuditContext::forProject($projectPath, $scanPaths, diffSinceRef: $diffSinceRef);
        $files = $this->filterByScanPaths($this->projectFileScanner->scan($projectPath), $scanPaths);
        if (null !== $diffSinceRef && $this->gitChangedFilesResolver instanceof GitChangedFilesResolverInterface) {
            $files = $this->filterByGitDiff($projectPath, $diffSinceRef, $files);
        }

        $auditContext->setProjectFiles($files);

        $fileContentPerRoundInput = 0;
        foreach ($files as $file) {
            $fileContentPerRoundInput += $this->tokenEstimator->estimateTokens($file->content(), $this->primaryModel);
        }

        $attackerPerRoundInput = $fileContentPerRoundInput + $this->skillPromptTokensAcrossChunks($files);

        if ($this->toolsEnabled) {
            $attackerPerRoundInput = (int) ceil($attackerPerRoundInput * $this->toolRoundTripMultiplier());
        }

        $attackerInputTokens = $attackerPerRoundInput * $this->maxIterations;
        $attackerOutputTokens = (int) ceil($attackerInputTokens * $this->outputRatio);
        $attackerCostUsd = $this->costCalculator->costForCall($attackerInputTokens, $attackerOutputTokens, $this->primaryModel);

        $reviewerModel = '' === $this->reviewerModel ? $this->primaryModel : $this->reviewerModel;
        $reviewerInputTokens = (int) ceil($fileContentPerRoundInput * $this->maxIterations * $this->reviewerInputRatio);
        $reviewerOutputTokens = (int) ceil($reviewerInputTokens * $this->outputRatio);
        $reviewerCostUsd = $this->costCalculator->costForCall($reviewerInputTokens, $reviewerOutputTokens, $reviewerModel);

        $estimatedInputTokens = $attackerInputTokens + $reviewerInputTokens;
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
     * `audit.max_tool_iterations` caps the tool-call rounds a chunk may take,
     * so it caps the conversation those rounds re-send. Scaling the calibrated
     * ratio by the configured bound keeps the estimate honest for a user who
     * lowers it to cut cost, instead of charging every run the calibrated
     * maximum.
     */
    private function toolRoundTripMultiplier(): float
    {
        return 1.0 + $this->toolRoundTripRatio * ($this->maxToolIterations / self::CALIBRATION_MAX_TOOL_ITERATIONS);
    }

    /**
     * The real run renders the skill block per chunk, filtered to that
     * chunk's own file types (`AttackerPromptBuilder::skillsForFiles()`).
     * Summing a per-chunk render here, instead of rendering once from the
     * whole project's type union and multiplying by the chunk count, keeps
     * the estimate accurate when `stable_system_prompt` is `false` and each
     * chunk pulls in a smaller skill subset than the project as a whole.
     *
     * @param list<ProjectFile> $files
     */
    private function skillPromptTokensAcrossChunks(array $files): int
    {
        $total = 0;
        foreach ($this->fileChunker->chunk($files) as $chunkFiles) {
            $total += $this->skillPromptTokens($chunkFiles);
        }

        return $total;
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
     * @param list<string>      $scanPaths
     *
     * @return list<ProjectFile>
     */
    private function filterByScanPaths(array $files, array $scanPaths): array
    {
        return ScanPathFilter::apply($files, $scanPaths);
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
