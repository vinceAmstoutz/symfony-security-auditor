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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Turns a single-finding review outcome — a verdict payload, a raw LLM
 * response, or a failure — into the reviewed finding plus its reviewer
 * coverage entry, so the accept/reject/error logic lives in one tested place.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReviewOutcomeRecorder
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public function __construct(
        private VerdictApplier $verdictApplier,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private LoggerInterface $logger,
        private ProgressReporterInterface $progressReporter,
    ) {}

    /**
     * A null payload — empty response or no recorded verdict — rejects the
     * finding.
     *
     * @param array<string, mixed>|list<array<string, mixed>>|null $review
     */
    public function recordVerdict(Vulnerability $vulnerability, ?array $review, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        if (null === $review) {
            ReviewerCoverageRecorder::record($vulnerability, 'rejected', $coverageRecorder, $this->progressReporter);
            $rejected = $vulnerability->withReviewerValidation(false);
            $coverageRecorder->recordReviewedFinding($rejected);

            return $rejected;
        }

        $reviewed = $this->verdictApplier->apply($vulnerability, $review);
        ReviewerCoverageRecorder::record(
            $reviewed,
            $reviewed->isReviewerValidated() ? 'validated' : 'rejected',
            $coverageRecorder,
            $this->progressReporter,
        );
        $coverageRecorder->recordReviewedFinding($reviewed);

        return $reviewed;
    }

    public function recordReviewError(Vulnerability $vulnerability, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        $this->logger->error('Reviewer LLM call failed', [
            'vulnerability_id' => $vulnerability->id(),
            'error' => $throwable->getMessage(),
        ]);
        ReviewerCoverageRecorder::record($vulnerability, 'errored', $coverageRecorder, $this->progressReporter);
        $errored = $vulnerability->withReviewerValidation(false);
        $coverageRecorder->recordReviewedFinding($errored);

        return $errored;
    }

    /**
     * Marks a finding the reviewer never reached because a budget/provider
     * abort unwound the review loop first — no logging, mirroring how
     * `ChunkCoverageRecorder` marks a chunk the attacker never reached.
     */
    public function recordUnreached(Vulnerability $vulnerability, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        ReviewerCoverageRecorder::record($vulnerability, $status, $coverageRecorder, $this->progressReporter);
    }

    public function applyResponse(Vulnerability $vulnerability, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder, ?string $codeContextForCache = null): Vulnerability
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
            ReviewerCoverageRecorder::record($vulnerability, 'errored', $coverageRecorder, $this->progressReporter);
            $errored = $vulnerability->withReviewerValidation(false);
            $coverageRecorder->recordReviewedFinding($errored);

            return $errored;
        }

        if (null !== $codeContextForCache) {
            $this->reviewerVerdictCache->store($vulnerability, $codeContextForCache, $this->verdictApplier->normalize($rawData));
        }

        return $this->recordVerdict($vulnerability, $rawData, $coverageRecorder);
    }
}
