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

/**
 * Typed, defensive reads of a progress-event context array. Reporters never
 * trust the payload shape (a custom emitter may pass anything), so a missing or
 * wrongly-typed key resolves to a neutral default rather than throwing.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProgressContext
{
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
        $seconds = \is_float($value) ? (int) round($value) : 0;

        return $seconds >= 1 ? \sprintf(' (%ds)', $seconds) : '';
    }
}
