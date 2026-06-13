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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchVerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentStructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\SequentialReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\StructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Orchestrates the reviewer pass: resolves the review mode (tools, structured
 * collection, batching, concurrency) and delegates each finding to the
 * matching `Review\` analysis strategy built here.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReviewerAgent implements ReviewerAgentInterface
{
    public const int DEFAULT_BATCH_SIZE = 1;

    public const int DEFAULT_MAX_TOOL_ITERATIONS = 4;

    public const bool DEFAULT_TOOLS_ENABLED = false;

    public const int DEFAULT_MAX_CONCURRENT = 1;

    public const bool DEFAULT_STRUCTURED_COLLECTION = true;

    private SequentialReviewAnalyzer $sequentialReviewAnalyzer;

    private ?StructuredReviewAnalyzer $structuredReviewAnalyzer;

    private ?ConcurrentReviewAnalyzer $concurrentReviewAnalyzer;

    private ?ConcurrentStructuredReviewAnalyzer $concurrentStructuredReviewAnalyzer;

    private BatchReviewAnalyzer $batchReviewAnalyzer;

    public function __construct(
        LLMClientInterface $llmClient,
        ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private LoggerInterface $logger,
        private int $batchSize = self::DEFAULT_BATCH_SIZE,
        private ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
        private bool $toolsEnabled = self::DEFAULT_TOOLS_ENABLED,
        int $maxToolIterations = self::DEFAULT_MAX_TOOL_ITERATIONS,
        private int $maxConcurrent = self::DEFAULT_MAX_CONCURRENT,
        ?RecordReviewToolFactoryInterface $recordReviewToolFactory = null,
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        ?ReviewerCacheInterface $reviewerCache = null,
    ) {
        $verdictApplier = new VerdictApplier($logger);
        $reviewerVerdictCache = new ReviewerVerdictCache($reviewerCache, $logger);
        $reviewOutcomeRecorder = new ReviewOutcomeRecorder($verdictApplier, $reviewerVerdictCache, $logger);

        $this->sequentialReviewAnalyzer = new SequentialReviewAnalyzer(
            $llmClient,
            $reviewerPromptBuilder,
            $reviewerVerdictCache,
            $reviewOutcomeRecorder,
            $maxToolIterations,
        );

        $this->structuredReviewAnalyzer = $recordReviewToolFactory instanceof RecordReviewToolFactoryInterface
            ? new StructuredReviewAnalyzer(
                $llmClient,
                $reviewerPromptBuilder,
                $reviewerVerdictCache,
                $reviewOutcomeRecorder,
                $recordReviewToolFactory,
                $logger,
                $maxToolIterations,
            )
            : null;

        $this->concurrentReviewAnalyzer = $llmClient instanceof BatchCapableLLMClientInterface
            ? new ConcurrentReviewAnalyzer(
                $llmClient,
                $reviewerPromptBuilder,
                $reviewerVerdictCache,
                $reviewOutcomeRecorder,
                $this->maxConcurrent,
            )
            : null;

        $this->concurrentStructuredReviewAnalyzer = $llmClient instanceof ToolBatchCapableLLMClientInterface && $recordReviewToolFactory instanceof RecordReviewToolFactoryInterface
            ? new ConcurrentStructuredReviewAnalyzer(
                $llmClient,
                $reviewerPromptBuilder,
                $reviewerVerdictCache,
                $reviewOutcomeRecorder,
                $recordReviewToolFactory,
                $logger,
                $this->maxConcurrent,
                $maxToolIterations,
            )
            : null;

        $this->batchReviewAnalyzer = new BatchReviewAnalyzer(
            $llmClient,
            $reviewerPromptBuilder,
            new BatchVerdictApplier($verdictApplier, $logger),
            $logger,
            $maxToolIterations,
            $recordReviewToolFactory,
        );
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    public function review(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false): array
    {
        if ([] === $vulnerabilities) {
            return [];
        }

        $useTools = $this->toolsEnabled && $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;
        $structuredEligible = !$useTools
            && $this->useStructuredCollection
            && $this->structuredReviewAnalyzer instanceof StructuredReviewAnalyzer;
        $useStructuredConcurrent = $structuredEligible
            && $this->batchSize <= 1
            && $this->maxConcurrent > 1
            && $this->concurrentStructuredReviewAnalyzer instanceof ConcurrentStructuredReviewAnalyzer;
        $useStructuredCollection = $structuredEligible
            && ($this->batchSize > 1 || $this->maxConcurrent <= 1 || $useStructuredConcurrent);
        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($projectFiles) : null;

        $this->logger->info('Reviewer agent validating findings', [
            'count' => \count($vulnerabilities),
            'batch_size' => $this->batchSize,
            'tools_enabled' => $useTools,
            'structured_collection' => $useStructuredCollection,
        ]);

        if ($this->batchSize <= 1) {
            if ($useStructuredConcurrent) {
                $reviewed = $this->concurrentStructuredReviewAnalyzer->analyze($vulnerabilities, $projectFiles, $coverageRecorder, $bypassCache);
            } elseif ($useStructuredCollection) {
                $reviewed = $this->structuredReviewAnalyzer->analyze($vulnerabilities, $projectFiles, $coverageRecorder, $bypassCache);
            } else {
                $useConcurrent = !$useTools
                    && $this->maxConcurrent > 1
                    && $this->concurrentReviewAnalyzer instanceof ConcurrentReviewAnalyzer;
                $reviewed = $useConcurrent
                    ? $this->concurrentReviewAnalyzer->analyze($vulnerabilities, $projectFiles, $coverageRecorder, $bypassCache)
                    : $this->sequentialReviewAnalyzer->analyze($vulnerabilities, $projectFiles, $coverageRecorder, $toolRegistry, $bypassCache);
            }
        } else {
            $reviewed = $this->batchReviewAnalyzer->analyze($vulnerabilities, $projectFiles, $this->batchSize, $coverageRecorder, $toolRegistry, $useStructuredCollection);
        }

        $accepted = array_filter($reviewed, static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated());
        $rejected = \count($reviewed) - \count($accepted);

        $this->logger->info('Reviewer agent complete', [
            'reviewed' => \count($reviewed),
            'accepted' => \count($accepted),
            'rejected' => $rejected,
        ]);

        return $reviewed;
    }
}
