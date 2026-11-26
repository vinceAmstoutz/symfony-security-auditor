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

use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
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
    private OversizedReviewBatchRecovery $oversizedReviewBatchRecovery;

    private ConcurrentReviewWindow $concurrentReviewWindow;

    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private BatchVerdictApplier $batchVerdictApplier,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private LoggerInterface $logger,
        private int $maxToolIterations,
        private ?RecordReviewToolFactoryInterface $recordReviewToolFactory,
        private BatchAnswerReader $batchAnswerReader,
    ) {
        $this->oversizedReviewBatchRecovery = new OversizedReviewBatchRecovery($batchVerdictApplier, $logger);
        $this->concurrentReviewWindow = new ConcurrentReviewWindow($llmClient, $reviewerPromptBuilder, $batchAnswerReader, $batchVerdictApplier, $this->oversizedReviewBatchRecovery, $logger, $maxToolIterations, $recordReviewToolFactory);
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
        [$batches, $missIndexes] = ReviewBatches::of($misses, $missIndexes, $reviewBatchSettings);
        $position = 0;
        foreach (array_chunk($batches, $this->concurrentReviewWindow->size($reviewBatchSettings), true) as $window) {
            try {
                $windowReviewed = $this->reviewWindow(array_values($window), $reviewBatchSettings, $reviewCacheBuckets);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemainingBatches($batches, array_key_last($window) + 1, 'aborted', $reviewBatchSettings->coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemainingBatches($batches, array_key_last($window) + 1, 'errored', $reviewBatchSettings->coverageRecorder);

                throw $llmProviderException;
            }

            foreach ($windowReviewed as $batchReviewed) {
                [$reviewed, $position] = $this->mergeBatchIntoReviewed($batchReviewed, $missIndexes, $position, $reviewed);
            }
        }

        return $reviewed;
    }

    /**
     * @param list<list<Vulnerability>> $window
     *
     * @return list<list<Vulnerability>>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function reviewWindow(array $window, ReviewBatchSettings $reviewBatchSettings, ReviewCacheBuckets $reviewCacheBuckets): array
    {
        if (1 < \count($window)) {
            return $this->concurrentReviewWindow->review($window, $reviewCacheBuckets, $reviewBatchSettings, fn (array $half): array => $this->reviewOneBatch($half, $reviewBatchSettings, $reviewCacheBuckets));
        }

        return [$this->reviewOneBatch($window[0], $reviewBatchSettings, $reviewCacheBuckets)];
    }

    /**
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function reviewOneBatch(array $batch, ReviewBatchSettings $reviewBatchSettings, ReviewCacheBuckets $reviewCacheBuckets): array
    {
        return $reviewBatchSettings->structured
            ? $this->reviewBatchViaStructuredCollection($batch, $reviewCacheBuckets->codeContexts, $reviewCacheBuckets->cacheContexts, $reviewBatchSettings->coverageRecorder)
            : $this->reviewBatch($batch, $reviewCacheBuckets->codeContexts, $reviewCacheBuckets->cacheContexts, $reviewBatchSettings->coverageRecorder, $reviewBatchSettings->toolRegistry);
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

            return $this->batchAnswerReader->readBatchAnswer($batch, $response, $cacheContexts, $coverageRecorder);
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

            return $this->batchAnswerReader->readStructuredBatchAnswer($batch, $llmResponse, $structuredReviewCollectionSession, $cacheContexts, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->batchAnswerReader->recordDrainedBatchOrMarkUnreached($batch, $structuredReviewCollectionSession, $cacheContexts, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->oversizedReviewBatchRecovery->recover(
                $batch,
                $llmRequestTooLargeException,
                $coverageRecorder,
                fn (array $half): array => $this->reviewBatchViaStructuredCollection($half, $codeContexts, $cacheContexts, $coverageRecorder),
            );
        } catch (LLMProviderException $llmProviderException) {
            $this->batchAnswerReader->recordDrainedBatchOrMarkUnreached($batch, $structuredReviewCollectionSession, $cacheContexts, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->batchAnswerReader->recordDrainedBatchOrError($batch, $structuredReviewCollectionSession, $cacheContexts, $exception, $coverageRecorder);
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
