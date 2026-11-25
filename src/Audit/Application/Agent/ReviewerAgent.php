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

use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchVerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentStructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewBatchSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\SequentialReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\StructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Runs the reviewer pass through the analyzer its review mode (tools,
 * structured collection, batching, concurrency) selects.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReviewerAgent implements ReviewerAgentInterface
{
    public const int DEFAULT_BATCH_SIZE = 1;

    public const int DEFAULT_MAX_TOOL_ITERATIONS = 4;

    public const bool DEFAULT_TOOLS_ENABLED = false;

    public const int DEFAULT_MAX_CONCURRENT = 1;

    public const bool DEFAULT_STRUCTURED_COLLECTION = true;

    public const int MAX_FILE_GROUP_SIZE = 20;

    private SequentialReviewAnalyzer $sequentialReviewAnalyzer;

    private ?StructuredReviewAnalyzer $structuredReviewAnalyzer;

    private ?ConcurrentReviewAnalyzer $concurrentReviewAnalyzer;

    private ?ConcurrentStructuredReviewAnalyzer $concurrentStructuredReviewAnalyzer;

    private BatchReviewAnalyzer $batchReviewAnalyzer;

    private BatchVerdictApplier $batchVerdictApplier;

    private LoggerInterface $logger;

    private int $batchSize;

    private bool $toolsEnabled;

    private int $maxConcurrent;

    private bool $useStructuredCollection;

    public function __construct(
        ReviewerAgentCollaborators $reviewerAgentCollaborators,
        ReviewerModeConfiguration $reviewerModeConfiguration,
        private ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
    ) {
        $this->logger = $reviewerAgentCollaborators->logger;
        $this->batchSize = $reviewerModeConfiguration->batchSize;
        $this->toolsEnabled = $reviewerModeConfiguration->toolsEnabled;
        $this->maxConcurrent = $reviewerModeConfiguration->maxConcurrent;
        $this->useStructuredCollection = $reviewerModeConfiguration->useStructuredCollection;

        $verdictApplier = new VerdictApplier($reviewerAgentCollaborators->logger);
        $reviewerVerdictCache = new ReviewerVerdictCache($reviewerAgentCollaborators->reviewerCache, $reviewerAgentCollaborators->logger);
        $reviewOutcomeRecorder = new ReviewOutcomeRecorder($verdictApplier, $reviewerVerdictCache, $reviewerAgentCollaborators->logger, $reviewerAgentCollaborators->progressReporter, $reviewerAgentCollaborators->triageMemoryRecorder);
        $recordingToolClients = RecordingToolClients::forReviewer($reviewerAgentCollaborators->logger);

        $this->sequentialReviewAnalyzer = new SequentialReviewAnalyzer(
            $reviewerAgentCollaborators->llmClient,
            $reviewerAgentCollaborators->reviewerPromptBuilder,
            $reviewerVerdictCache,
            $reviewOutcomeRecorder,
            $reviewerModeConfiguration->maxToolIterations,
        );

        $this->structuredReviewAnalyzer = $reviewerAgentCollaborators->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface
            ? new StructuredReviewAnalyzer(
                $reviewerAgentCollaborators->llmClient,
                $reviewerAgentCollaborators->reviewerPromptBuilder,
                $reviewerVerdictCache,
                $reviewOutcomeRecorder,
                $reviewerAgentCollaborators->recordReviewToolFactory,
                $reviewerAgentCollaborators->logger,
                $reviewerModeConfiguration->maxToolIterations,
                $recordingToolClients,
            )
            : null;

        $this->concurrentReviewAnalyzer = $reviewerAgentCollaborators->llmClient instanceof BatchCapableLLMClientInterface
            ? new ConcurrentReviewAnalyzer(
                $reviewerAgentCollaborators->llmClient,
                $reviewerAgentCollaborators->reviewerPromptBuilder,
                $reviewerVerdictCache,
                $reviewOutcomeRecorder,
                $reviewerModeConfiguration->maxConcurrent,
            )
            : null;

        $this->concurrentStructuredReviewAnalyzer = $reviewerAgentCollaborators->llmClient instanceof ToolBatchCapableLLMClientInterface && $reviewerAgentCollaborators->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface
            ? new ConcurrentStructuredReviewAnalyzer(
                $reviewerAgentCollaborators->llmClient,
                $reviewerAgentCollaborators->reviewerPromptBuilder,
                $reviewerVerdictCache,
                $reviewOutcomeRecorder,
                $reviewerAgentCollaborators->recordReviewToolFactory,
                $reviewerAgentCollaborators->logger,
                $reviewerModeConfiguration->maxConcurrent,
                $reviewerModeConfiguration->maxToolIterations,
                $recordingToolClients,
            )
            : null;

        $this->batchVerdictApplier = new BatchVerdictApplier($verdictApplier, $reviewerVerdictCache, $reviewerAgentCollaborators->logger, $reviewerAgentCollaborators->progressReporter, $reviewerAgentCollaborators->triageMemoryRecorder);
        $this->batchReviewAnalyzer = new BatchReviewAnalyzer(
            $reviewerAgentCollaborators->llmClient,
            $reviewerAgentCollaborators->reviewerPromptBuilder,
            $this->batchVerdictApplier,
            $reviewerVerdictCache,
            $reviewOutcomeRecorder,
            $reviewerAgentCollaborators->logger,
            $reviewerModeConfiguration->maxToolIterations,
            $reviewerAgentCollaborators->recordReviewToolFactory,
            $recordingToolClients,
        );
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     * @param ?list<ProjectFile>  $toolFiles
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[Override]
    public function review(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false, ?array $toolFiles = null): array
    {
        if ([] === $vulnerabilities) {
            return [];
        }

        $useTools = $this->toolsEnabled && $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;
        $codeContextFiles = [...$projectFiles, ...($toolFiles ?? [])];
        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($toolFiles ?? $projectFiles) : null;
        $structuredEligible = $this->isStructuredEligible($useTools);
        $structuredConcurrent = $this->structuredConcurrentAnalyzer($structuredEligible);
        $useStructuredCollection = $this->shouldUseStructuredCollection($structuredEligible, $structuredConcurrent instanceof ConcurrentStructuredReviewAnalyzer);
        $structured = $useStructuredCollection ? $this->structuredReviewAnalyzer : null;
        $concurrent = $this->concurrentAnalyzer($useTools);

        $this->logger->info('Reviewer agent validating findings', [
            'count' => \count($vulnerabilities),
            'batch_size' => $this->batchSize,
            'tools_enabled' => $useTools,
            'structured_collection' => $useStructuredCollection,
        ]);

        $reviewed = match (true) {
            $this->batchSize > 1 => $this->batchReviewAnalyzer->analyze($vulnerabilities, $codeContextFiles, new ReviewBatchSettings($this->batchSize, $useStructuredCollection, $bypassCache, $coverageRecorder, $toolRegistry)),
            $structuredConcurrent instanceof ConcurrentStructuredReviewAnalyzer => $structuredConcurrent->analyze($vulnerabilities, $codeContextFiles, $coverageRecorder, $bypassCache),
            $structured instanceof StructuredReviewAnalyzer => $structured->analyze($vulnerabilities, $codeContextFiles, $coverageRecorder, $bypassCache),
            $concurrent instanceof ConcurrentReviewAnalyzer => $concurrent->analyze($vulnerabilities, $codeContextFiles, $coverageRecorder, $bypassCache),
            default => $this->sequentialReviewAnalyzer->analyze($vulnerabilities, $codeContextFiles, $coverageRecorder, $toolRegistry, $bypassCache),
        };

        $accepted = array_filter($reviewed, static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated());
        $rejected = \count($reviewed) - \count($accepted);

        $this->logger->info('Reviewer agent complete', [
            'reviewed' => \count($reviewed),
            'accepted' => \count($accepted),
            'rejected' => $rejected,
        ]);

        return $reviewed;
    }

    /**
     * Reviews the findings that share a file with another in calls of at most
     * {@see self::MAX_FILE_GROUP_SIZE} findings of one file, so the file is
     * sent once per call, and the others as {@see self::review()} does. An
     * abort before the grouped calls marks their findings unreached.
     *
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     * @param ?list<ProjectFile>  $toolFiles
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[Override]
    public function reviewByFile(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false, ?array $toolFiles = null): array
    {
        [$alone, $grouped] = $this->splitByFileGroup($vulnerabilities);

        try {
            $reviewed = $this->review($alone, $projectFiles, $coverageRecorder, $bypassCache, $toolFiles);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->batchVerdictApplier->markBatchUnreached($grouped, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->batchVerdictApplier->markBatchUnreached($grouped, 'errored', $coverageRecorder);

            throw $llmProviderException;
        }

        $useTools = $this->toolsEnabled && $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;
        $reviewBatchSettings = new ReviewBatchSettings(
            self::MAX_FILE_GROUP_SIZE,
            $this->isStructuredEligible($useTools),
            $bypassCache,
            $coverageRecorder,
            $useTools ? $this->toolRegistryFactory->forProjectFiles($toolFiles ?? $projectFiles) : null,
            true,
        );

        return [...$reviewed, ...$this->batchReviewAnalyzer->analyze($grouped, [...$projectFiles, ...($toolFiles ?? [])], $reviewBatchSettings)];
    }

    /**
     * Splits the findings into those alone in their file and those sharing it
     * with another.
     *
     * @param list<Vulnerability> $findings
     *
     * @return array{list<Vulnerability>, list<Vulnerability>}
     */
    private function splitByFileGroup(array $findings): array
    {
        $countByFile = array_count_values(array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->filePath(), $findings));
        $isAlone = static fn (Vulnerability $vulnerability): bool => 1 === $countByFile[$vulnerability->filePath()];

        return [
            array_values(array_filter($findings, $isAlone)),
            array_values(array_filter($findings, static fn (Vulnerability $vulnerability): bool => !$isAlone($vulnerability))),
        ];
    }

    private function isStructuredEligible(bool $useTools): bool
    {
        return !$useTools
            && $this->useStructuredCollection
            && $this->structuredReviewAnalyzer instanceof StructuredReviewAnalyzer;
    }

    private function shouldUseStructuredCollection(bool $structuredEligible, bool $useStructuredConcurrent): bool
    {
        return $structuredEligible
            && ($this->batchSize > 1 || $this->maxConcurrent <= 1 || $useStructuredConcurrent);
    }

    private function structuredConcurrentAnalyzer(bool $structuredEligible): ?ConcurrentStructuredReviewAnalyzer
    {
        if (!$structuredEligible || $this->batchSize > 1 || $this->maxConcurrent <= 1) {
            return null;
        }

        return $this->concurrentStructuredReviewAnalyzer;
    }

    private function concurrentAnalyzer(bool $useTools): ?ConcurrentReviewAnalyzer
    {
        if ($useTools || $this->maxConcurrent <= 1) {
            return null;
        }

        return $this->concurrentReviewAnalyzer;
    }
}
