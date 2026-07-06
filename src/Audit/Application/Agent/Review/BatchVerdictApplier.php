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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Turns a batch review outcome into the reviewed findings plus their reviewer
 * coverage entries: matches verdicts to findings by id (an unmatched finding
 * is rejected), and degrades a whole failed batch to rejected/errored.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BatchVerdictApplier
{
    public function __construct(
        private VerdictApplier $verdictApplier,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private LoggerInterface $logger,
        private ProgressReporterInterface $progressReporter,
    ) {}

    /**
     * A finding whose id appears in `$codeContexts` has its matched verdict
     * persisted to the reviewer cache, so a subsequent batched run reuses it
     * instead of calling the LLM again. Bypassed runs pass no contexts.
     *
     * @param list<Vulnerability>      $batch
     * @param array<int|string, mixed> $rawData
     * @param array<string, string>    $codeContexts
     *
     * @return list<Vulnerability>
     */
    public function applyBatchReview(array $batch, array $rawData, CoverageRecorderInterface $coverageRecorder, array $codeContexts = []): array
    {
        $reviewsById = $this->indexReviewsById($rawData);

        $reviewed = [];
        foreach ($batch as $vulnerability) {
            $reviewed[] = $this->reviewVulnerability(
                $vulnerability,
                $reviewsById[$vulnerability->id()] ?? null,
                $coverageRecorder,
                $codeContexts,
            );
        }

        return $reviewed;
    }

    /**
     * @param array<int|string, mixed> $rawData
     *
     * @return array<string, array<string, mixed>>
     */
    private function indexReviewsById(array $rawData): array
    {
        $reviewsById = [];
        foreach ($this->asReviewList($rawData) as $entry) {
            if (!\is_array($entry)) {
                continue;
            }

            $entryId = $entry['id'] ?? null;
            if (\is_string($entryId)) {
                $reviewsById[$entryId] = $this->withStringKeys($entry);
            }
        }

        return $reviewsById;
    }

    /**
     * A batch of one may come back as a bare review object instead of a
     * one-element array — treat it as a single-entry list rather than
     * iterating its scalar values.
     *
     * @param array<int|string, mixed> $rawData
     *
     * @return list<mixed>
     */
    private function asReviewList(array $rawData): array
    {
        return [] !== $rawData && !array_is_list($rawData) ? [$rawData] : $rawData;
    }

    /**
     * @param array<int|string, mixed> $entry
     *
     * @return array<string, mixed>
     */
    private function withStringKeys(array $entry): array
    {
        $stringKeyed = [];
        foreach ($entry as $key => $value) {
            $stringKeyed[(string) $key] = $value;
        }

        return $stringKeyed;
    }

    /**
     * @param array<string, mixed>|null $review
     * @param array<string, string>     $codeContexts
     */
    private function reviewVulnerability(Vulnerability $vulnerability, ?array $review, CoverageRecorderInterface $coverageRecorder, array $codeContexts): Vulnerability
    {
        if (null === $review) {
            ReviewerCoverageRecorder::record($vulnerability, 'rejected', $coverageRecorder, $this->progressReporter);

            return $vulnerability->withReviewerValidation(false);
        }

        if (\array_key_exists($vulnerability->id(), $codeContexts)) {
            $this->reviewerVerdictCache->store($vulnerability, $codeContexts[$vulnerability->id()], $review);
        }

        $applied = $this->verdictApplier->apply($vulnerability, $review);
        ReviewerCoverageRecorder::record(
            $applied,
            $applied->isReviewerValidated() ? 'validated' : 'rejected',
            $coverageRecorder,
            $this->progressReporter,
        );

        return $applied;
    }

    /**
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     */
    public function rejectBatch(array $batch, CoverageRecorderInterface $coverageRecorder): array
    {
        $rejected = [];
        foreach ($batch as $vulnerability) {
            $rejected[] = $vulnerability->withReviewerValidation(false);
            ReviewerCoverageRecorder::record($vulnerability, 'rejected', $coverageRecorder, $this->progressReporter);
        }

        return $rejected;
    }

    /**
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     */
    public function markBatchErrored(array $batch, CoverageRecorderInterface $coverageRecorder): array
    {
        $errored = [];
        foreach ($batch as $vulnerability) {
            $errored[] = $vulnerability->withReviewerValidation(false);
            ReviewerCoverageRecorder::record($vulnerability, 'errored', $coverageRecorder, $this->progressReporter);
        }

        return $errored;
    }

    /**
     * Marks every finding in a batch the reviewer never reached because a
     * budget abort unwound the batch loop first — no logging, mirroring
     * `markBatchErrored()`.
     *
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     */
    public function markBatchAborted(array $batch, CoverageRecorderInterface $coverageRecorder): array
    {
        $aborted = [];
        foreach ($batch as $vulnerability) {
            $aborted[] = $vulnerability->withReviewerValidation(false);
            ReviewerCoverageRecorder::record($vulnerability, 'aborted', $coverageRecorder, $this->progressReporter);
        }

        return $aborted;
    }

    /**
     * Logs a failed batch LLM call and marks every finding in the batch
     * errored, so the error log + coverage live in a single tested place for
     * both the JSON batch path and the structured `record_review` batch path.
     *
     * @param list<Vulnerability> $batch
     *
     * @return list<Vulnerability>
     */
    public function recordBatchError(array $batch, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): array
    {
        $this->logger->error('Reviewer batch LLM call failed', [
            'batch_size' => \count($batch),
            'error' => $throwable->getMessage(),
        ]);

        return $this->markBatchErrored($batch, $coverageRecorder);
    }
}
