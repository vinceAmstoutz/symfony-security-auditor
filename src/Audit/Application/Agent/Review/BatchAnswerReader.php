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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * Reads the verdicts of a review batch's answer, or of the `record_review`
 * calls of its conversation, matching them back to findings by id.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class BatchAnswerReader
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public function __construct(
        private LLMClientInterface $llmClient,
        private BatchVerdictApplier $batchVerdictApplier,
        private LoggerInterface $logger,
        private RecordingToolClients $recordingToolClients,
    ) {}

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     */
    public function readBatchAnswer(array $batch, LLMResponse $llmResponse, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
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
     * Reads the verdicts recorded through `record_review`, or those of the
     * JSON answer when the client never offered the tool.
     *
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     */
    public function readStructuredBatchAnswer(array $batch, LLMResponse $llmResponse, StructuredReviewCollectionSession $structuredReviewCollectionSession, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
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
     * Keeps the verdicts recorded through `record_review` before the batch's
     * conversation failed and records the batch as an error when none was.
     *
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     */
    public function recordDrainedBatchOrError(array $batch, ?StructuredReviewCollectionSession $structuredReviewCollectionSession, array $cacheContexts, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): array
    {
        $rawData = $structuredReviewCollectionSession?->drain() ?? [];

        return [] !== $rawData
            ? $this->applyPartialBatchReviewInOriginalOrder($batch, $rawData, $cacheContexts, $coverageRecorder, false)
            : $this->batchVerdictApplier->recordBatchError($batch, $throwable, $coverageRecorder);
    }

    /**
     * Keeps the verdicts recorded through `record_review` before the batch's
     * conversation aborted and marks each member without one as `$status`,
     * without the warning about a verdict left out.
     *
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     */
    public function recordDrainedBatchOrMarkUnreached(array $batch, ?StructuredReviewCollectionSession $structuredReviewCollectionSession, array $cacheContexts, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        $rawData = $structuredReviewCollectionSession?->drain() ?? [];
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
}
