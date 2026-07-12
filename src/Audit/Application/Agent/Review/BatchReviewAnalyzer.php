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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Reviews findings in batches of `batchSize`: one LLM call per batch, verdicts
 * matched back to findings by id. The structured mode collects verdicts
 * through a `record_review` tool; the JSON mode parses the model's array
 * response, optionally with the investigation tool registry. Cached verdicts
 * are served first; only the cache-miss findings are batched and dispatched to
 * the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BatchReviewAnalyzer
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private BatchVerdictApplier $batchVerdictApplier,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private LoggerInterface $logger,
        private int $maxToolIterations,
        private ?RecordReviewToolFactoryInterface $recordReviewToolFactory,
    ) {}

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
     */
    private function reviewBatch(array $batch, array $codeContexts, array $cacheContexts, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): array
    {
        [$systemPrompt, $userMessage] = $this->buildBatchPrompts($batch, $codeContexts);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            if ($response->isEmpty()) {
                return $this->batchVerdictApplier->rejectBatch($batch, $coverageRecorder);
            }

            /** @var array<int|string, mixed> $rawData */
            $rawData = $response->parseJson();

            return $this->batchVerdictApplier->applyBatchReview($batch, $rawData, $coverageRecorder, $cacheContexts);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->batchVerdictApplier->markBatchUnreached($batch, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->batchVerdictApplier->markBatchUnreached($batch, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (JsonException $exception) {
            $this->logger->error('Failed to parse reviewer batch response', [
                'batch_size' => \count($batch),
                'error' => $exception->getMessage(),
                'content_preview' => substr($response->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);

            return $this->batchVerdictApplier->markBatchErrored($batch, $coverageRecorder);
        } catch (Throwable $exception) {
            return $this->batchVerdictApplier->recordBatchError($batch, $exception, $coverageRecorder);
        }
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
            $this->llmClient->completeWithTools($systemPrompt, $userMessage, $structuredReviewCollectionSession->toolRegistry, $this->maxToolIterations);

            return $this->batchVerdictApplier->applyBatchReview($batch, $structuredReviewCollectionSession->drain(), $coverageRecorder, $cacheContexts);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->recordDrainedBatchOrMarkUnreached($batch, $structuredReviewCollectionSession, $cacheContexts, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->recordDrainedBatchOrMarkUnreached($batch, $structuredReviewCollectionSession, $cacheContexts, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (Throwable $exception) {
            $rawData = $structuredReviewCollectionSession->drain();

            return [] !== $rawData
                ? $this->applyPartialBatchReviewInOriginalOrder($batch, $rawData, $cacheContexts, $coverageRecorder)
                : $this->batchVerdictApplier->recordBatchError($batch, $exception, $coverageRecorder);
        }
    }

    /**
     * A batch member absent from `$rawData` because the conversation was cut
     * off before it was ever considered must not be routed through
     * {@see BatchVerdictApplier::applyBatchReview()}, which treats a missing
     * verdict as an implicit rejection — it is marked errored instead, like a
     * fully-empty drain. `mergeBatchIntoReviewed()` maps this method's return
     * value back to the caller's findings purely by position, so the result
     * is reassembled in `$batch`'s original order rather than concatenating
     * the reviewed and errored groups.
     *
     * @param list<Vulnerability>      $batch
     * @param array<int|string, mixed> $rawData
     * @param array<string, string>    $cacheContexts
     *
     * @return list<Vulnerability>
     */
    private function applyPartialBatchReviewInOriginalOrder(array $batch, array $rawData, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        [$reachedBatch, $unreachedBatch] = $this->partitionByReached($batch, $rawData);

        $byId = [];
        foreach ($this->batchVerdictApplier->applyBatchReview($reachedBatch, $rawData, $coverageRecorder, $cacheContexts) as $vulnerability) {
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
     * Recovers any verdicts the LLM already recorded via `record_review` tool
     * calls in an earlier round of this batch's conversation before a later
     * round aborted it — otherwise they vanish with the exception even
     * though they were genuinely reached. A batch member with no matching
     * verdict is marked not-reached rather than routed through
     * {@see BatchVerdictApplier::applyBatchReview()}, which would otherwise
     * treat its absence as an implicit rejection — correct when the model
     * finished the batch and chose not to flag it, but wrong when the
     * conversation was cut off before it was ever considered. Falls back to
     * the existing not-reached handling for the whole batch only when
     * nothing was recorded at all.
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
