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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use JsonException;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordingToolClients;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Reviews the cache-miss findings in batches of `batchSize`, one LLM call per
 * batch, matching verdicts back to findings by id. Splits a batch the model
 * cannot take in whole instead of aborting the review.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class BatchReviewAnalyzer
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    private OversizedReviewBatchRecovery $oversizedReviewBatchRecovery;

    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private BatchVerdictApplier $batchVerdictApplier,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private LoggerInterface $logger,
        private int $maxToolIterations,
        private ?RecordReviewToolFactoryInterface $recordReviewToolFactory,
        private RecordingToolClients $recordingToolClients,
    ) {
        $this->oversizedReviewBatchRecovery = new OversizedReviewBatchRecovery($batchVerdictApplier, $logger);
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function analyze(array $vulnerabilities, array $projectFiles, ReviewBatchSettings $reviewBatchSettings): array
    {
        $cachePartition = $this->partitionByCache($vulnerabilities, $projectFiles, $reviewBatchSettings);

        $cacheContexts = $reviewBatchSettings->bypassCache ? [] : $cachePartition->codeContexts;
        $reviewCacheBuckets = new ReviewCacheBuckets($cachePartition->codeContexts, $cacheContexts);

        $reviewed = $this->reviewMissesInBatches($cachePartition->reviewed, $cachePartition->misses, $cachePartition->missIndexes, $reviewBatchSettings, $reviewCacheBuckets);

        ksort($reviewed);

        return array_values($reviewed);
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     */
    private function partitionByCache(array $vulnerabilities, array $projectFiles, ReviewBatchSettings $reviewBatchSettings): CachePartition
    {
        $codeContexts = [];
        $reviewed = [];
        $missIndexes = [];
        $misses = [];

        foreach ($vulnerabilities as $index => $vulnerability) {
            $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);
            $codeContexts[$vulnerability->id()] = $codeContext;

            $cached = $this->reviewerVerdictCache->get($vulnerability, $codeContext, $reviewBatchSettings->bypassCache);
            if (null !== $cached) {
                $reviewed[$index] = $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $cached, $reviewBatchSettings->coverageRecorder);

                continue;
            }

            $missIndexes[] = $index;
            $misses[] = $vulnerability;
        }

        return new CachePartition($codeContexts, $reviewed, $missIndexes, $misses);
    }

    /**
     * @param array<int, Vulnerability> $reviewed
     * @param list<Vulnerability>       $misses
     * @param list<int>                 $missIndexes
     *
     * @return array<int, Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function reviewMissesInBatches(array $reviewed, array $misses, array $missIndexes, ReviewBatchSettings $reviewBatchSettings, ReviewCacheBuckets $reviewCacheBuckets): array
    {
        $batches = array_chunk($misses, $reviewBatchSettings->batchSize);
        $position = 0;
        foreach ($batches as $batchNumber => $batch) {
            try {
                $batchReviewed = $reviewBatchSettings->structured
                    ? $this->reviewBatchViaStructuredCollection($batch, $reviewCacheBuckets->codeContexts, $reviewCacheBuckets->cacheContexts, $reviewBatchSettings->coverageRecorder)
                    : $this->reviewBatch($batch, $reviewCacheBuckets->codeContexts, $reviewCacheBuckets->cacheContexts, $reviewBatchSettings->coverageRecorder, $reviewBatchSettings->toolRegistry);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemainingBatches($batches, $batchNumber + 1, 'aborted', $reviewBatchSettings->coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemainingBatches($batches, $batchNumber + 1, 'errored', $reviewBatchSettings->coverageRecorder);

                throw $llmProviderException;
            }

            [$reviewed, $position] = $this->mergeBatchIntoReviewed($batchReviewed, $missIndexes, $position, $reviewed);
        }

        return $reviewed;
    }

    /**
     * @param list<list<Vulnerability>> $batches
     */
    private function failRemainingBatches(array $batches, int $fromBatchNumber, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($batches as $batchNumber => $batch) {
            if ($batchNumber < $fromBatchNumber) {
                continue;
            }

            $this->batchVerdictApplier->markBatchUnreached($batch, $status, $coverageRecorder);
        }
    }

    /**
     * @param list<Vulnerability>       $batchReviewed
     * @param list<int>                 $missIndexes
     * @param array<int, Vulnerability> $reviewed
     *
     * @return array{0: array<int, Vulnerability>, 1: int}
     */
    private function mergeBatchIntoReviewed(array $batchReviewed, array $missIndexes, int $position, array $reviewed): array
    {
        foreach ($batchReviewed as $reviewedVulnerability) {
            $reviewed[$missIndexes[$position]] = $reviewedVulnerability;
            ++$position;
        }

        return [$reviewed, $position];
    }

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $codeContexts
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function reviewBatch(array $batch, array $codeContexts, array $cacheContexts, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): array
    {
        [$systemPrompt, $userMessage] = $this->buildBatchPrompts($batch, $codeContexts);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            return $this->readBatchAnswer($batch, $response, $cacheContexts, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->batchVerdictApplier->markBatchUnreached($batch, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->oversizedReviewBatchRecovery->recover(
                $batch,
                $llmRequestTooLargeException,
                $coverageRecorder,
                fn (array $half): array => $this->reviewBatch($half, $codeContexts, $cacheContexts, $coverageRecorder, $toolRegistry),
            );
        } catch (LLMProviderException $llmProviderException) {
            $this->batchVerdictApplier->markBatchUnreached($batch, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->batchVerdictApplier->recordBatchError($batch, $exception, $coverageRecorder);
        }
    }

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     */
    private function readBatchAnswer(array $batch, LLMResponse $llmResponse, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        try {
            return $this->applyBatchResponse($batch, $llmResponse, ReviewerVerdictCache::contextsFor($llmResponse, $cacheContexts), $coverageRecorder);
        } catch (JsonException $jsonException) {
            $this->logger->error('Failed to parse reviewer batch response', [
                'batch_size' => \count($batch),
                'error' => $jsonException->getMessage(),
                'content_preview' => substr($llmResponse->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);

            return $this->batchVerdictApplier->markBatchErrored($batch, $coverageRecorder);
        }
    }

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     *
     * @throws JsonException
     */
    private function applyBatchResponse(array $batch, LLMResponse $llmResponse, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        if ($llmResponse->isDegraded()) {
            return $this->applyIncompleteBatch($batch, $llmResponse, $llmResponse->isEmpty() ? [] : $llmResponse->parseJson(), $cacheContexts, $coverageRecorder);
        }

        if ($llmResponse->isEmpty()) {
            return $this->batchVerdictApplier->recordEmptyAnswer($batch, $coverageRecorder);
        }

        /** @var array<int|string, mixed> $rawData */
        $rawData = $llmResponse->parseJson();

        return $this->batchVerdictApplier->applyBatchReview($batch, $rawData, $coverageRecorder, $cacheContexts, $llmResponse->reachedToolCap());
    }

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $codeContexts
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function reviewBatchViaStructuredCollection(array $batch, array $codeContexts, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        \assert($this->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface);

        [$systemPrompt, $userMessage] = $this->buildBatchPrompts($batch, $codeContexts);

        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin($this->recordReviewToolFactory, $this->logger);

        try {
            $llmResponse = $this->llmClient->completeWithTools($systemPrompt, $userMessage, $structuredReviewCollectionSession->toolRegistry, $this->maxToolIterations);

            return $this->readStructuredBatchAnswer($batch, $llmResponse, $structuredReviewCollectionSession, $cacheContexts, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->recordDrainedBatchOrMarkUnreached($batch, $structuredReviewCollectionSession, $cacheContexts, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->oversizedReviewBatchRecovery->recover(
                $batch,
                $llmRequestTooLargeException,
                $coverageRecorder,
                fn (array $half): array => $this->reviewBatchViaStructuredCollection($half, $codeContexts, $cacheContexts, $coverageRecorder),
            );
        } catch (LLMProviderException $llmProviderException) {
            $this->recordDrainedBatchOrMarkUnreached($batch, $structuredReviewCollectionSession, $cacheContexts, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (Throwable $exception) {
            $rawData = $structuredReviewCollectionSession->drain();

            return [] !== $rawData
                ? $this->applyPartialBatchReviewInOriginalOrder($batch, $rawData, $cacheContexts, $coverageRecorder, false)
                : $this->batchVerdictApplier->recordBatchError($batch, $exception, $coverageRecorder);
        }
    }

    /**
     * Reads the verdicts recorded through `record_review`, or those of the
     * JSON answer when the client never offered the tool.
     *
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     */
    private function readStructuredBatchAnswer(array $batch, LLMResponse $llmResponse, StructuredReviewCollectionSession $structuredReviewCollectionSession, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        $this->recordingToolClients->note($this->llmClient, $structuredReviewCollectionSession->recordingToolReached());
        if ($this->recordingToolClients->ignoresTools($this->llmClient)) {
            return $this->readBatchAnswer($batch, $llmResponse, $cacheContexts, $coverageRecorder);
        }

        $rawData = $structuredReviewCollectionSession->drain();

        return $llmResponse->isDegraded()
            ? $this->applyIncompleteBatch($batch, $llmResponse, $rawData, $cacheContexts, $coverageRecorder)
            : $this->batchVerdictApplier->applyBatchReview($batch, $rawData, $coverageRecorder, ReviewerVerdictCache::contextsFor($llmResponse, $cacheContexts), $llmResponse->reachedToolCap());
    }

    /**
     * Applies the verdicts of a degraded answer and records the members it
     * does not name as errored, never as rejected and cached.
     *
     * @param list<Vulnerability>      $batch
     * @param array<int|string, mixed> $rawData
     * @param array<string, string>    $cacheContexts
     *
     * @return list<Vulnerability>
     */
    private function applyIncompleteBatch(array $batch, LLMResponse $llmResponse, array $rawData, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        $this->logger->warning('Reviewer batch response was cut short; the findings it never reached are recorded as errored', [
            'batch_size' => \count($batch),
            'stop_reason' => $llmResponse->stopReason(),
            'verdicts_kept' => \count($this->batchVerdictApplier->reachedIds($rawData)),
        ]);

        return $this->applyPartialBatchReviewInOriginalOrder($batch, $rawData, ReviewerVerdictCache::contextsFor($llmResponse, $cacheContexts), $coverageRecorder, $llmResponse->reachedToolCap());
    }

    /**
     * Marks a member absent from `$rawData` errored without the warning about
     * a verdict left out. Returns the findings in `$batch` order, which
     * `mergeBatchIntoReviewed()` maps back by position.
     *
     * @param list<Vulnerability>      $batch
     * @param array<int|string, mixed> $rawData
     * @param array<string, string>    $cacheContexts
     *
     * @return list<Vulnerability>
     */
    private function applyPartialBatchReviewInOriginalOrder(array $batch, array $rawData, array $cacheContexts, CoverageRecorderInterface $coverageRecorder, bool $atToolCap): array
    {
        [$reachedBatch, $unreachedBatch] = $this->partitionByReached($batch, $rawData);

        $byId = [];
        foreach ($this->batchVerdictApplier->applyBatchReview($reachedBatch, $rawData, $coverageRecorder, $cacheContexts, $atToolCap) as $vulnerability) {
            $byId[$vulnerability->id()] = $vulnerability;
        }

        foreach ($this->batchVerdictApplier->markBatchErrored($unreachedBatch, $coverageRecorder) as $vulnerability) {
            $byId[$vulnerability->id()] = $vulnerability;
        }

        return array_map(static fn (Vulnerability $vulnerability): Vulnerability => $byId[$vulnerability->id()], $batch);
    }

    /**
     * @param list<Vulnerability>      $batch
     * @param array<int|string, mixed> $rawData
     *
     * @return array{0: list<Vulnerability>, 1: list<Vulnerability>}
     */
    private function partitionByReached(array $batch, array $rawData): array
    {
        $reachedIds = $this->batchVerdictApplier->reachedIds($rawData);

        return [
            array_values(array_filter($batch, static fn (Vulnerability $vulnerability): bool => \in_array($vulnerability->id(), $reachedIds, true))),
            array_values(array_filter($batch, static fn (Vulnerability $vulnerability): bool => !\in_array($vulnerability->id(), $reachedIds, true))),
        ];
    }

    /**
     * Keeps the verdicts recorded through `record_review` before the batch's
     * conversation aborted and marks each member without one as `$status`,
     * without the warning about a verdict left out.
     *
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     */
    private function recordDrainedBatchOrMarkUnreached(array $batch, StructuredReviewCollectionSession $structuredReviewCollectionSession, array $cacheContexts, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        $rawData = $structuredReviewCollectionSession->drain();
        if ([] === $rawData) {
            $this->batchVerdictApplier->markBatchUnreached($batch, $status, $coverageRecorder);

            return;
        }

        [$reachedBatch, $unreachedBatch] = $this->partitionByReached($batch, $rawData);

        if ([] !== $reachedBatch) {
            $this->batchVerdictApplier->applyBatchReview($reachedBatch, $rawData, $coverageRecorder, $cacheContexts);
        }

        if ([] !== $unreachedBatch) {
            $this->batchVerdictApplier->markBatchUnreached($unreachedBatch, $status, $coverageRecorder);
        }
    }

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $codeContexts
     *
     * @return array{0: string, 1: string}
     */
    private function buildBatchPrompts(array $batch, array $codeContexts): array
    {
        return [
            $this->reviewerPromptBuilder->buildBatchSystemPrompt(),
            $this->reviewerPromptBuilder->buildBatchUserMessage($batch, $codeContexts),
        ];
    }
}
