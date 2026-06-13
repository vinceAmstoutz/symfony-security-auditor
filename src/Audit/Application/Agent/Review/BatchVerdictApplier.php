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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

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
        private LoggerInterface $logger,
    ) {}

    /**
     * @param list<Vulnerability>      $batch
     * @param array<int|string, mixed> $rawData
     *
     * @return list<Vulnerability>
     */
    public function applyBatchReview(array $batch, array $rawData, CoverageRecorderInterface $coverageRecorder): array
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

            $applied = $this->verdictApplier->apply($vulnerability, $review);
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
    public function rejectBatch(array $batch, CoverageRecorderInterface $coverageRecorder): array
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
    public function markBatchErrored(array $batch, CoverageRecorderInterface $coverageRecorder): array
    {
        $errored = [];
        foreach ($batch as $vulnerability) {
            $errored[] = $vulnerability->withReviewerValidation(false);
            $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), 'errored');
        }

        return $errored;
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
