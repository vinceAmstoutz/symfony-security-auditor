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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

/**
 * Walks the ingestion stage of the audit pipeline, estimates how many tokens
 * an actual run would consume, and returns an `AuditReport` carrying the
 * estimate as its `AuditCost`. Never invokes the LLM platform — `--dry-run`
 * stays free regardless of project size.
 *
 * Estimation strategy: every scanned file contributes its content to a
 * synthetic "attacker prompt" (input). Output tokens are projected at
 * `outputRatio * input` because audit prompts are heavily input-skewed.
 * Multiplied by `max_iterations` to account for the attacker/reviewer loop.
 */
final readonly class EstimateAuditCostUseCase
{
    /** Conservative output:input ratio observed across reference audits. */
    public const float DEFAULT_OUTPUT_RATIO = 0.15;

    public function __construct(
        private ProjectFileScannerInterface $projectFileScanner,
        private TokenEstimatorInterface $tokenEstimator,
        private CostCalculator $costCalculator,
        private LoggerInterface $logger,
        private string $primaryModel = '',
        private int $maxIterations = 3,
        private float $outputRatio = self::DEFAULT_OUTPUT_RATIO,
    ) {}

    public function execute(string $projectPath): AuditReport
    {
        $this->logger->info('Estimating audit cost (dry-run)', ['project' => $projectPath]);

        $auditContext = AuditContext::forProject($projectPath);
        $files = $this->projectFileScanner->scan($projectPath);
        $auditContext->setProjectFiles($files);

        $totalInputChars = 0;
        foreach ($files as $file) {
            $totalInputChars += mb_strlen($file->content());
        }

        $perRoundInputTokens = $this->tokenEstimator->estimateTokens(str_repeat('x', $totalInputChars), $this->primaryModel);
        $estimatedInputTokens = $perRoundInputTokens * $this->maxIterations;
        $estimatedOutputTokens = (int) ceil($estimatedInputTokens * $this->outputRatio);
        $estimatedCostUsd = $this->costCalculator->costForCall($estimatedInputTokens, $estimatedOutputTokens, $this->primaryModel);

        $auditCost = AuditCost::of($estimatedInputTokens, $estimatedOutputTokens, $estimatedCostUsd, $this->primaryModel);

        $this->logger->info('Dry-run estimate ready', [
            'files' => \count($files),
            'input_tokens' => $estimatedInputTokens,
            'output_tokens' => $estimatedOutputTokens,
            'estimated_cost_usd' => $estimatedCostUsd,
        ]);

        return AuditReport::fromContext($auditContext, $auditCost);
    }
}
