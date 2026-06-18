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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
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
     */
    public function analyze(array $vulnerabilities, array $projectFiles, ReviewBatchSettings $settings): array
    {
        $partition = $this->partitionByCache($vulnerabilities, $projectFiles, $settings);

        $cacheContexts = $settings->bypassCache ? [] : $partition->codeContexts;
        $buckets = new ReviewCacheBuckets($partition->codeContexts, $cacheContexts);

        $reviewed = $partition->reviewed;
        $this->reviewMissesInBatches($partition->misses, $partition->missIndexes, $settings, $buckets, $reviewed);

        ksort($reviewed);

        return array_values($reviewed);
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     */
    private function partitionByCache(array $vulnerabilities, array $projectFiles, ReviewBatchSettings $settings): CachePartition
    {
        $codeContexts = [];
        $reviewed = [];
        $missIndexes = [];
        $misses = [];

        foreach ($vulnerabilities as $index => $vulnerability) {
            $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);
            $codeContexts[$vulnerability->id()] = $codeContext;

            $cached = $this->reviewerVerdictCache->get($vulnerability, $codeContext, $settings->bypassCache);
            if (null !== $cached) {
                $reviewed[$index] = $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $cached, $settings->coverageRecorder);

                continue;
            }

            $missIndexes[] = $index;
            $misses[] = $vulnerability;
        }

        return new CachePartition($codeContexts, $reviewed, $missIndexes, $misses);
    }

    /**
     * @param list<Vulnerability>           $misses
     * @param list<int>                     $missIndexes
     * @param array<int, Vulnerability>     $reviewed
     *
     * @param-out array<int, Vulnerability> $reviewed
     */
    private function reviewMissesInBatches(array $misses, array $missIndexes, ReviewBatchSettings $settings, ReviewCacheBuckets $buckets, array &$reviewed): void
    {
        $position = 0;
        foreach (array_chunk($misses, $settings->batchSize) as $batch) {
            $batchReviewed = $settings->structured
                ? $this->reviewBatchViaStructuredCollection($batch, $buckets->codeContexts, $buckets->cacheContexts, $settings->coverageRecorder)
                : $this->reviewBatch($batch, $buckets->codeContexts, $buckets->cacheContexts, $settings->coverageRecorder, $settings->toolRegistry);

            $position = $this->mergeBatchIntoReviewed($batchReviewed, $missIndexes, $position, $reviewed);
        }
    }

    /**
     * @param list<Vulnerability>           $batchReviewed
     * @param list<int>                     $missIndexes
     * @param array<int, Vulnerability>     $reviewed
     *
     * @param-out array<int, Vulnerability> $reviewed
     */
    private function mergeBatchIntoReviewed(array $batchReviewed, array $missIndexes, int $position, array &$reviewed): int
    {
        foreach ($batchReviewed as $reviewedVulnerability) {
            $reviewed[$missIndexes[$position]] = $reviewedVulnerability;
            ++$position;
        }

        return $position;
    }

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $codeContexts
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
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
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
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
     */
    private function reviewBatchViaStructuredCollection(array $batch, array $codeContexts, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        \assert($this->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface);

        [$systemPrompt, $userMessage] = $this->buildBatchPrompts($batch, $codeContexts);

        $reviewCollector = new ReviewCollector();
        $toolRegistry = new ToolRegistry([$this->recordReviewToolFactory->create($reviewCollector)], $this->logger);

        try {
            $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations);

            return $this->batchVerdictApplier->applyBatchReview($batch, $reviewCollector->drain(), $coverageRecorder, $cacheContexts);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->batchVerdictApplier->recordBatchError($batch, $exception, $coverageRecorder);
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
