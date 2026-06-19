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
use ValueError;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

/**
 * Applies one reviewer verdict payload to a finding: acceptance, optional
 * severity elevation, and optional type correction. Invalid enum values from
 * the model are logged and ignored, keeping the original finding values.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class VerdictApplier
{
    public function __construct(
        private LoggerInterface $logger,
    ) {}

    /**
     * @param array<string, mixed>|list<array<string, mixed>> $reviewData
     */
    public function apply(Vulnerability $vulnerability, array $reviewData): Vulnerability
    {
        $review = $this->normalize($reviewData);

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

        $reviewed = $this->applyAdjustedSeverity($reviewed, $adjustedSeverity);
        $reviewed = $this->applyCorrectedType($reviewed, $correctedType);

        $this->logReviewDecision($vulnerability, $accepted, $review);

        return $reviewed;
    }

    private function applyAdjustedSeverity(Vulnerability $vulnerability, ?string $adjustedSeverity): Vulnerability
    {
        if (null === $adjustedSeverity) {
            return $vulnerability;
        }

        try {
            return $vulnerability->withElevatedSeverity(VulnerabilitySeverity::from($adjustedSeverity));
        } catch (ValueError) {
            $this->logger->debug('Reviewer returned invalid severity, keeping original', [
                'adjusted_severity' => $adjustedSeverity,
            ]);

            return $vulnerability;
        }
    }

    private function applyCorrectedType(Vulnerability $vulnerability, ?string $correctedType): Vulnerability
    {
        if (null === $correctedType) {
            return $vulnerability;
        }

        try {
            return $vulnerability->withCorrectedType(VulnerabilityType::from($correctedType));
        } catch (ValueError) {
            $this->logger->debug('Reviewer returned invalid corrected_type, keeping original', [
                'corrected_type' => $correctedType,
            ]);

            return $vulnerability;
        }
    }

    /**
     * Normalizes the reviewer payload to the single review object: a defensive
     * unwrap when the model returns a one-element array instead of an object.
     *
     * @param array<string, mixed>|list<array<string, mixed>> $reviewData
     *
     * @return array<string, mixed>
     */
    public function normalize(array $reviewData): array
    {
        $candidate = \is_array($reviewData[0] ?? null) ? $reviewData[0] : $reviewData;

        $review = [];
        foreach ($candidate as $key => $value) {
            $review[(string) $key] = $value;
        }

        return $review;
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
