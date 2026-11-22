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
 * Reads a progress-event context: a missing or wrongly typed key yields a
 * neutral default, never an exception.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
     * Returns an elapsed-time suffix in whole seconds, empty when the value is
     * not a float or is under one second.
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
     * Returns the reason a chunk failed as a one-line suffix, empty when the
     * event names none.
     *
     * @param array<string, mixed> $context
     */
    public static function failureReasonSuffix(array $context): string
    {
        $reason = trim(TerminalTextSanitizer::collapseToSingleLine(self::string($context, 'reason')));

        return '' === $reason ? '' : \sprintf(' — %s', $reason);
    }

    /**
     * Whether a `review.finding.reviewed` event reports a review that failed
     * or was aborted, so neither validated nor rejected the finding.
     *
     * @param array<string, mixed> $context
     */
    public static function reviewReachedNoVerdict(array $context): bool
    {
        return \in_array(self::string($context, 'status'), self::NO_VERDICT_REVIEW_STATUSES, true);
    }

    /**
     * The validated and rejected counts of a `review.completed` event, then
     * the failed count when it is not zero.
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
