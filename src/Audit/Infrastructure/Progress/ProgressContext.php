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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TerminalTextSanitizer;

/**
 * Typed, defensive reads of a progress-event context array. Reporters never
 * trust the payload shape (a custom emitter may pass anything), so a missing or
 * wrongly-typed key resolves to a neutral default rather than throwing.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProgressContext
{
    private const array NO_VERDICT_REVIEW_STATUSES = ['errored', 'aborted'];

    /** @param array<string, mixed> $context */
    public static function int(array $context, string $key): int
    {
        $value = $context[$key] ?? null;

        return \is_int($value) ? $value : 0;
    }

    /** @param array<string, mixed> $context */
    public static function string(array $context, string $key): string
    {
        $value = $context[$key] ?? null;

        return \is_string($value) ? $value : '';
    }

    /**
     * Renders an elapsed duration as a trailing " (Ns)" suffix in whole seconds,
     * or an empty string when the value is missing, not a float, or rounds below
     * one second (e.g. cache hits and concurrently-dispatched chunks, which have
     * no meaningful per-chunk wall time).
     *
     * @param array<string, mixed> $context
     */
    public static function durationSuffix(array $context, string $key): string
    {
        $value = $context[$key] ?? null;

        if (!\is_float($value) || $value < 1.0) {
            return '';
        }

        return \sprintf(' (%ds)', (int) round($value));
    }

    /**
     * Renders the reason a chunk failed as a trailing " — reason" suffix on one
     * line, or an empty string when the event names none.
     *
     * @param array<string, mixed> $context
     */
    public static function failureReasonSuffix(array $context): string
    {
        $reason = trim(TerminalTextSanitizer::collapseToSingleLine(self::string($context, 'reason')));

        return '' === $reason ? '' : \sprintf(' — %s', $reason);
    }

    /**
     * Whether a `review.finding.reviewed` event reports a review that reached
     * no verdict — its call failed, or an abort stopped it — rather than a
     * finding the reviewer validated or rejected.
     *
     * @param array<string, mixed> $context
     */
    public static function reviewReachedNoVerdict(array $context): bool
    {
        return \in_array(self::string($context, 'status'), self::NO_VERDICT_REVIEW_STATUSES, true);
    }

    /**
     * The tally of a `review.completed` event: the findings validated and
     * rejected, then how many reviews failed when some did.
     *
     * @param array<string, mixed> $context
     */
    public static function reviewTally(array $context): string
    {
        $tally = \sprintf('%d validated, %d rejected', self::int($context, 'accepted'), self::int($context, 'rejected'));
        $failed = self::int($context, 'failed');

        return 0 === $failed ? $tally : \sprintf('%s, %d failed', $tally, $failed);
    }
}
