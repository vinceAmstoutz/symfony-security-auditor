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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullTriageMemoryRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;

/**
 * Turns a single-finding review outcome (a verdict payload, a raw answer or a
 * failure) into the reviewed finding and its coverage entry.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReviewOutcomeRecorder
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public function __construct(
        private VerdictApplier $verdictApplier,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private LoggerInterface $logger,
        private ProgressReporterInterface $progressReporter,
        private TriageMemoryRecorderInterface $triageMemoryRecorder = new NullTriageMemoryRecorder(),
    ) {}

    /**
     * Records the finding as errored, never as rejected, when the payload is
     * null or has no `accepted` flag. A rejection given at the tool-call limit
     * is applied but kept out of triage memory, as it is out of the cache.
     *
     * @param array<string, mixed>|list<array<string, mixed>>|null $review
     */
    public function recordVerdict(Vulnerability $vulnerability, ?array $review, CoverageRecorderInterface $coverageRecorder, bool $atToolCap = false): Vulnerability
    {
        if (null === $review || !$this->verdictApplier->hasVerdict($review)) {
            return $this->recordUnjudged($vulnerability, $coverageRecorder);
        }

        $reviewed = $this->verdictApplier->apply($vulnerability, $review);
        ReviewerCoverageRecorder::record(
            $reviewed,
            $reviewed->isReviewerValidated() ? 'validated' : 'rejected',
            $coverageRecorder,
            $this->progressReporter,
        );
        $coverageRecorder->recordReviewedFinding($reviewed);

        if (!$atToolCap) {
            RejectionTriageRecorder::record($this->verdictApplier, $this->triageMemoryRecorder, $reviewed, $review);
        }

        return $reviewed;
    }

    public function recordReviewError(Vulnerability $vulnerability, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        $this->logger->error('Reviewer LLM call failed', [
            'vulnerability_id' => $vulnerability->id(),
            'error' => $throwable->getMessage(),
        ]);

        return $this->recordErrored($vulnerability, $coverageRecorder);
    }

    /**
     * Records the finding of a degraded answer as errored and uncached, never
     * as rejected.
     */
    public function recordIncompleteResponse(Vulnerability $vulnerability, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        $this->logger->warning('Reviewer response was cut short; the finding is recorded as errored and left out of the cache', [
            'vulnerability_id' => $vulnerability->id(),
            'stop_reason' => $llmResponse->stopReason(),
        ]);

        return $this->recordErrored($vulnerability, $coverageRecorder);
    }

    private function recordUnjudged(Vulnerability $vulnerability, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        $this->logger->warning('Reviewer reached no verdict for the finding; it is recorded as errored and left out of the cache', [
            'vulnerability_id' => $vulnerability->id(),
        ]);

        return $this->recordErrored($vulnerability, $coverageRecorder);
    }

    private function recordErrored(Vulnerability $vulnerability, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        ReviewerCoverageRecorder::record($vulnerability, 'errored', $coverageRecorder, $this->progressReporter);
        $errored = $vulnerability->withReviewerValidation(false);
        $coverageRecorder->recordReviewedFinding($errored);

        return $errored;
    }

    /**
     * Marks, without logging, a finding a budget or provider abort kept the
     * reviewer from reaching.
     */
    public function recordUnreached(Vulnerability $vulnerability, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        ReviewerCoverageRecorder::record($vulnerability, $status, $coverageRecorder, $this->progressReporter);
    }

    /**
     * Applies a verdict recorded through `record_review` before the
     * conversation aborted, caching it when `$codeContextForCache` is given.
     * Returns null when nothing was recorded.
     */
    public function recoverDrainedVerdict(Vulnerability $vulnerability, StructuredReviewCollectionSession $structuredReviewCollectionSession, CoverageRecorderInterface $coverageRecorder, ?string $codeContextForCache = null): ?Vulnerability
    {
        $verdicts = $structuredReviewCollectionSession->drain();
        if ([] === $verdicts) {
            return null;
        }

        $verdict = array_pop($verdicts);
        if (null !== $codeContextForCache) {
            $this->reviewerVerdictCache->store($vulnerability, $codeContextForCache, $verdict);
        }

        return $this->recordVerdict($vulnerability, $verdict, $coverageRecorder);
    }

    public function applyResponse(Vulnerability $vulnerability, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder, ?string $codeContextForCache = null): Vulnerability
    {
        if ($llmResponse->isDegraded()) {
            return $this->recordIncompleteResponse($vulnerability, $llmResponse, $coverageRecorder);
        }

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

            return $this->recordErrored($vulnerability, $coverageRecorder);
        }

        $cacheContext = ReviewerVerdictCache::contextFor($llmResponse, $codeContextForCache);
        if (null !== $cacheContext) {
            $this->reviewerVerdictCache->store($vulnerability, $cacheContext, $this->verdictApplier->normalize($rawData));
        }

        return $this->recordVerdict($vulnerability, $rawData, $coverageRecorder, $llmResponse->reachedToolCap());
    }
}
