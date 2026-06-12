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

use JsonException;
use Psr\Log\LoggerInterface;
use Throwable;
use ValueError;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReviewerAgent implements ReviewerAgentInterface
{
    public const int DEFAULT_BATCH_SIZE = 1;

    public const int DEFAULT_MAX_TOOL_ITERATIONS = 4;

    public const bool DEFAULT_TOOLS_ENABLED = false;

    public const int DEFAULT_MAX_CONCURRENT = 1;

    public const bool DEFAULT_STRUCTURED_COLLECTION = true;

    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private LoggerInterface $logger,
        private int $batchSize = self::DEFAULT_BATCH_SIZE,
        private ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
        private bool $toolsEnabled = self::DEFAULT_TOOLS_ENABLED,
        private int $maxToolIterations = self::DEFAULT_MAX_TOOL_ITERATIONS,
        private int $maxConcurrent = self::DEFAULT_MAX_CONCURRENT,
        private ?RecordReviewToolFactoryInterface $recordReviewToolFactory = null,
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        private ?ReviewerCacheInterface $reviewerCache = null,
    ) {}

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
        $useStructuredCollection = !$useTools
            && $this->maxConcurrent <= 1
            && $this->useStructuredCollection
            && $this->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface;
        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($projectFiles) : null;

        $this->logger->info('Reviewer agent validating findings', [
            'count' => \count($vulnerabilities),
            'batch_size' => $this->batchSize,
            'tools_enabled' => $useTools,
            'structured_collection' => $useStructuredCollection,
        ]);

        $reviewed = [];

        if ($this->batchSize <= 1) {
            if ($useStructuredCollection) {
                $reviewed = $this->reviewSinglesViaStructuredCollection($vulnerabilities, $projectFiles, $coverageRecorder, $bypassCache);
            } else {
                $reviewed = $this->canReviewConcurrently($useTools)
                    ? $this->reviewSinglesConcurrently($vulnerabilities, $projectFiles, $coverageRecorder)
                    : $this->reviewSinglesSequentially($vulnerabilities, $projectFiles, $coverageRecorder, $toolRegistry, $bypassCache);
            }
        } else {
            foreach (array_chunk($vulnerabilities, $this->batchSize) as $batch) {
                $reviewed = [
                    ...$reviewed,
                    ...$useStructuredCollection
                        ? $this->reviewBatchViaStructuredCollection($batch, $projectFiles, $coverageRecorder)
                        : $this->reviewBatch($batch, $projectFiles, $coverageRecorder, $toolRegistry),
                ];
            }
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

    /**
     * @param list<Vulnerability> $batch
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    private function reviewBatch(array $batch, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): array
    {
        $codeContexts = [];
        foreach ($batch as $vulnerability) {
            $codeContexts[$vulnerability->id()] = $this->getFileContext($vulnerability->filePath(), $projectFiles);
        }

        $systemPrompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();
        $userMessage = $this->reviewerPromptBuilder->buildBatchUserMessage($batch, $codeContexts);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            if ($response->isEmpty()) {
                return $this->rejectBatch($batch, $coverageRecorder);
            }

            /** @var array<int|string, mixed> $rawData */
            $rawData = $response->parseJson();

            return $this->applyBatchReview($batch, $rawData, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (JsonException $exception) {
            $this->logger->error('Failed to parse reviewer batch response', [
                'batch_size' => \count($batch),
                'error' => $exception->getMessage(),
                'content_preview' => substr($response->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);

            return $this->markBatchErrored($batch, $coverageRecorder);
        } catch (Throwable $exception) {
            return $this->recordBatchError($batch, $exception, $coverageRecorder);
        }
    }

    /**
     * Logs a failed batch LLM call and marks every finding in the batch errored.
     * Shared by the JSON batch path and the structured `record_review` batch
     * path so the error log + coverage live in a single tested place.
     *
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     */
    private function recordBatchError(array $batch, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): array
    {
        $this->logger->error('Reviewer batch LLM call failed', [
            'batch_size' => \count($batch),
            'error' => $throwable->getMessage(),
        ]);

        return $this->markBatchErrored($batch, $coverageRecorder);
    }

    /**
     * @param list<Vulnerability>      $batch
     * @param array<int|string, mixed> $rawData
     *
     * @return list<Vulnerability>
     */
    private function applyBatchReview(array $batch, array $rawData, CoverageRecorderInterface $coverageRecorder): array
    {
        $reviewsById = [];
        foreach ($rawData as $entry) {
            if (!\is_array($entry)) {
                continue;
            }

            $entryId = $entry['id'] ?? null;
            if (\is_string($entryId)) {
                $stringKeyed = [];
                foreach ($entry as $key => $value) {
                    $stringKeyed[(string) $key] = $value;
                }

                $reviewsById[$entryId] = $stringKeyed;
            }
        }

        $reviewed = [];
        foreach ($batch as $vulnerability) {
            $review = $reviewsById[$vulnerability->id()] ?? null;

            if (null === $review) {
                $reviewed[] = $vulnerability->withReviewerValidation(false);
                $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'rejected');

                continue;
            }

            $applied = $this->applyReview($vulnerability, $review);
            $coverageRecorder->recordCoverage(
                AgentRole::Reviewer->value,
                $vulnerability->filePath(),
                $applied->isReviewerValidated() ? 'validated' : 'rejected',
            );
            $reviewed[] = $applied;
        }

        return $reviewed;
    }

    /**
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     */
    private function rejectBatch(array $batch, CoverageRecorderInterface $coverageRecorder): array
    {
        $rejected = [];
        foreach ($batch as $vulnerability) {
            $rejected[] = $vulnerability->withReviewerValidation(false);
            $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'rejected');
        }

        return $rejected;
    }

    /**
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     */
    private function markBatchErrored(array $batch, CoverageRecorderInterface $coverageRecorder): array
    {
        $errored = [];
        foreach ($batch as $vulnerability) {
            $errored[] = $vulnerability->withReviewerValidation(false);
            $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'errored');
        }

        return $errored;
    }

    private function canReviewConcurrently(bool $useTools): bool
    {
        return !$useTools
            && $this->maxConcurrent > 1
            && $this->llmClient instanceof BatchCapableLLMClientInterface;
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    private function reviewSinglesSequentially(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, bool $bypassCache): array
    {
        $reviewed = [];
        foreach ($vulnerabilities as $vulnerability) {
            $reviewed[] = $this->reviewSingle($vulnerability, $projectFiles, $coverageRecorder, $toolRegistry, $bypassCache);
        }

        return $reviewed;
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    private function reviewSinglesViaStructuredCollection(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): array
    {
        $reviewed = [];
        foreach ($vulnerabilities as $vulnerability) {
            $reviewed[] = $this->reviewSingleViaStructuredCollection($vulnerability, $projectFiles, $coverageRecorder, $bypassCache);
        }

        return $reviewed;
    }

    /**
     * @param list<ProjectFile> $projectFiles
     */
    private function reviewSingleViaStructuredCollection(Vulnerability $vulnerability, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): Vulnerability
    {
        \assert($this->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface);

        $codeContext = $this->getFileContext($vulnerability->filePath(), $projectFiles);

        $useCache = !$bypassCache && $this->reviewerCache instanceof ReviewerCacheInterface;
        $cached = $this->cachedVerdict($vulnerability, $codeContext, $useCache);
        if (null !== $cached) {
            return $this->recordVerdict($vulnerability, $cached, $coverageRecorder);
        }

        $systemPrompt = $this->reviewerPromptBuilder->buildSystemPrompt();
        $userMessage = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext);

        $reviewCollector = new ReviewCollector();
        $toolRegistry = new ToolRegistry([$this->recordReviewToolFactory->create($reviewCollector)], $this->logger);

        try {
            $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations);

            $verdict = $reviewCollector->drain()[0] ?? null;
            if ($useCache && null !== $verdict) {
                $this->reviewerCache->store($vulnerability, $codeContext, $verdict);
            }

            return $this->recordVerdict($vulnerability, $verdict, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->recordReviewError($vulnerability, $exception, $coverageRecorder);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function cachedVerdict(Vulnerability $vulnerability, string $codeContext, bool $useCache): ?array
    {
        if (!$useCache || !$this->reviewerCache instanceof ReviewerCacheInterface) {
            return null;
        }

        $cached = $this->reviewerCache->get($vulnerability, $codeContext);
        if (null === $cached) {
            return null;
        }

        $this->logger->debug('Reviewer verdict served from cache', ['vulnerability_id' => $vulnerability->id()]);

        return $cached;
    }

    /**
     * @param list<Vulnerability> $batch
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    private function reviewBatchViaStructuredCollection(array $batch, array $projectFiles, CoverageRecorderInterface $coverageRecorder): array
    {
        \assert($this->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface);

        $codeContexts = [];
        foreach ($batch as $vulnerability) {
            $codeContexts[$vulnerability->id()] = $this->getFileContext($vulnerability->filePath(), $projectFiles);
        }

        $systemPrompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();
        $userMessage = $this->reviewerPromptBuilder->buildBatchUserMessage($batch, $codeContexts);

        $reviewCollector = new ReviewCollector();
        $toolRegistry = new ToolRegistry([$this->recordReviewToolFactory->create($reviewCollector)], $this->logger);

        try {
            $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations);

            return $this->applyBatchReview($batch, $reviewCollector->drain(), $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->recordBatchError($batch, $exception, $coverageRecorder);
        }
    }

    /**
     * Resolves every single-finding review in concurrency windows via the
     * batch-capable client, then applies each verdict. Budget and non-transient
     * provider failures propagate (the batch client rethrows them); per-finding
     * parse/transient failures degrade to a rejected verdict exactly as the
     * sequential path does.
     *
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    private function reviewSinglesConcurrently(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder): array
    {
        \assert($this->llmClient instanceof BatchCapableLLMClientInterface);

        $requests = [];
        foreach ($vulnerabilities as $vulnerability) {
            $codeContext = $this->getFileContext($vulnerability->filePath(), $projectFiles);
            $requests[] = [
                'system' => $this->reviewerPromptBuilder->buildSystemPrompt(),
                'user' => $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext),
            ];
        }

        $responses = $this->llmClient->completeBatch($requests, $this->maxConcurrent);

        $reviewed = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $reviewed[] = $this->applyResponse($vulnerability, $responses[$index], $coverageRecorder);
        }

        return $reviewed;
    }

    /**
     * @param list<ProjectFile> $projectFiles
     */
    private function reviewSingle(Vulnerability $vulnerability, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, bool $bypassCache): Vulnerability
    {
        $codeContext = $this->getFileContext($vulnerability->filePath(), $projectFiles);

        $useCache = !$bypassCache && $this->reviewerCache instanceof ReviewerCacheInterface;
        $cached = $this->cachedVerdict($vulnerability, $codeContext, $useCache);
        if (null !== $cached) {
            return $this->recordVerdict($vulnerability, $cached, $coverageRecorder);
        }

        $systemPrompt = $this->reviewerPromptBuilder->buildSystemPrompt();
        $userMessage = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            return $this->applyResponse($vulnerability, $response, $coverageRecorder, $useCache ? $codeContext : null);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->recordReviewError($vulnerability, $exception, $coverageRecorder);
        }
    }

    private function applyResponse(Vulnerability $vulnerability, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder, ?string $codeContextForCache = null): Vulnerability
    {
        if ($llmResponse->isEmpty()) {
            return $this->recordVerdict($vulnerability, null, $coverageRecorder);
        }

        try {
            /** @var array<string, mixed>|list<array<string, mixed>> $rawData */
            $rawData = $llmResponse->parseJson();
        } catch (JsonException $jsonException) {
            $this->logger->error('Failed to parse reviewer response', [
                'vulnerability_id' => $vulnerability->id(),
                'error' => $jsonException->getMessage(),
                'content_preview' => substr($llmResponse->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);
            $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'errored');

            return $vulnerability->withReviewerValidation(false);
        }

        if (null !== $codeContextForCache && $this->reviewerCache instanceof ReviewerCacheInterface) {
            $this->reviewerCache->store($vulnerability, $codeContextForCache, $this->extractSingleReview($rawData));
        }

        return $this->recordVerdict($vulnerability, $rawData, $coverageRecorder);
    }

    /**
     * Applies one verdict payload to a finding and records reviewer coverage.
     * Shared by the JSON path (`applyResponse`), the cache-hit path, and the
     * structured `record_review` path so the accept/reject coverage logic lives
     * in a single tested place. A null payload — empty response or no recorded
     * verdict — rejects the finding.
     *
     * @param array<string, mixed>|list<array<string, mixed>>|null $review
     */
    private function recordVerdict(Vulnerability $vulnerability, ?array $review, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        if (null === $review) {
            $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'rejected');

            return $vulnerability->withReviewerValidation(false);
        }

        $reviewed = $this->applyReview($vulnerability, $review);
        $coverageRecorder->recordCoverage(
            AgentRole::Reviewer->value,
            $vulnerability->filePath(),
            $reviewed->isReviewerValidated() ? 'validated' : 'rejected',
        );

        return $reviewed;
    }

    private function recordReviewError(Vulnerability $vulnerability, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        $this->logger->error('Reviewer LLM call failed', [
            'vulnerability_id' => $vulnerability->id(),
            'error' => $throwable->getMessage(),
        ]);
        $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'errored');

        return $vulnerability->withReviewerValidation(false);
    }

    /**
     * @param array<string, mixed>|list<array<string, mixed>> $reviewData
     */
    private function applyReview(Vulnerability $vulnerability, array $reviewData): Vulnerability
    {
        $review = $this->extractSingleReview($reviewData);

        $accepted = (bool) ($review['accepted'] ?? false);
        $rawSeverity = $review['adjusted_severity'] ?? null;
        $adjustedSeverity = \is_string($rawSeverity) ? $rawSeverity : null;
        $rawCorrectedType = $review['corrected_type'] ?? null;
        $correctedType = \is_string($rawCorrectedType) ? $rawCorrectedType : null;

        $reviewed = $vulnerability->withReviewerValidation($accepted);

        if (!$accepted) {
            $this->logReviewDecision($vulnerability, $accepted, $review);

            return $reviewed;
        }

        if (null !== $adjustedSeverity) {
            try {
                $severity = VulnerabilitySeverity::from($adjustedSeverity);
                $reviewed = $reviewed->withElevatedSeverity($severity);
            } catch (ValueError) {
                $this->logger->debug('Reviewer returned invalid severity, keeping original', [
                    'adjusted_severity' => $adjustedSeverity,
                ]);
            }
        }

        if (null !== $correctedType) {
            try {
                $type = VulnerabilityType::from($correctedType);
                $reviewed = $reviewed->withCorrectedType($type);
            } catch (ValueError) {
                $this->logger->debug('Reviewer returned invalid corrected_type, keeping original', [
                    'corrected_type' => $correctedType,
                ]);
            }
        }

        $this->logReviewDecision($vulnerability, $accepted, $review);

        return $reviewed;
    }

    /**
     * @param list<ProjectFile> $projectFiles
     */
    private function getFileContext(string $filePath, array $projectFiles): string
    {
        foreach ($projectFiles as $projectFile) {
            if ($projectFile->relativePath() === $filePath) {
                return $projectFile->content();
            }
        }

        return '';
    }

    /**
     * Normalizes the reviewer payload to the single review object: a defensive
     * unwrap when the model returns a one-element array instead of an object.
     *
     * @param array<string, mixed>|list<array<string, mixed>> $reviewData
     *
     * @return array<string, mixed>
     */
    private function extractSingleReview(array $reviewData): array
    {
        $candidate = isset($reviewData[0]) && \is_array($reviewData[0]) ? $reviewData[0] : $reviewData;

        $review = [];
        foreach ($candidate as $key => $value) {
            $review[(string) $key] = $value;
        }

        return $review;
    }

    /** @param array<string, mixed> $review */
    private function logReviewDecision(Vulnerability $vulnerability, bool $accepted, array $review): void
    {
        $rawNotes = $review['reviewer_notes'] ?? null;
        $this->logger->debug('Vulnerability reviewed', [
            'id' => $vulnerability->id(),
            'accepted' => $accepted,
            'notes' => \is_string($rawNotes) ? $rawNotes : '',
        ]);
    }
}
