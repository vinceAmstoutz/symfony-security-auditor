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
    ) {}

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    public function review(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder): array
    {
        if ([] === $vulnerabilities) {
            return [];
        }

        $useTools = $this->toolsEnabled && $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;
        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($projectFiles) : null;

        $this->logger->info('Reviewer agent validating findings', [
            'count' => \count($vulnerabilities),
            'batch_size' => $this->batchSize,
            'tools_enabled' => $useTools,
        ]);

        $reviewed = [];

        if ($this->batchSize <= 1) {
            $reviewed = $this->canReviewConcurrently($useTools)
                ? $this->reviewSinglesConcurrently($vulnerabilities, $projectFiles, $coverageRecorder)
                : $this->reviewSinglesSequentially($vulnerabilities, $projectFiles, $coverageRecorder, $toolRegistry);
        } else {
            foreach (array_chunk($vulnerabilities, $this->batchSize) as $batch) {
                $reviewed = [...$reviewed, ...$this->reviewBatch($batch, $projectFiles, $coverageRecorder, $toolRegistry)];
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
            $this->logger->error('Reviewer batch LLM call failed', [
                'batch_size' => \count($batch),
                'error' => $exception->getMessage(),
            ]);

            return $this->markBatchErrored($batch, $coverageRecorder);
        }
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
    private function reviewSinglesSequentially(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): array
    {
        $reviewed = [];
        foreach ($vulnerabilities as $vulnerability) {
            $reviewed[] = $this->reviewSingle($vulnerability, $projectFiles, $coverageRecorder, $toolRegistry);
        }

        return $reviewed;
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
    private function reviewSingle(Vulnerability $vulnerability, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): Vulnerability
    {
        $codeContext = $this->getFileContext($vulnerability->filePath(), $projectFiles);
        $systemPrompt = $this->reviewerPromptBuilder->buildSystemPrompt();
        $userMessage = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            return $this->applyResponse($vulnerability, $response, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            $this->logger->error('Reviewer LLM call failed', [
                'vulnerability_id' => $vulnerability->id(),
                'error' => $exception->getMessage(),
            ]);
            $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'errored');

            return $vulnerability->withReviewerValidation(false);
        }
    }

    private function applyResponse(Vulnerability $vulnerability, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        if ($llmResponse->isEmpty()) {
            $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'rejected');

            return $vulnerability->withReviewerValidation(false);
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

        $reviewed = $this->applyReview($vulnerability, $rawData);
        $coverageRecorder->recordCoverage(
            AgentRole::Reviewer->value,
            $vulnerability->filePath(),
            $reviewed->isReviewerValidated() ? 'validated' : 'rejected',
        );

        return $reviewed;
    }

    /**
     * @param array<string, mixed>|list<array<string, mixed>> $reviewData
     */
    private function applyReview(Vulnerability $vulnerability, array $reviewData): Vulnerability
    {
        /** @var array<string, mixed> $review */
        $review = isset($reviewData[0]) && \is_array($reviewData[0]) ? $reviewData[0] : $reviewData;

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
