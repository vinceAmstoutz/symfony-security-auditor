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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

use InvalidArgumentException;

final class InvalidAuditExecutionConfigurationException extends InvalidArgumentException
{
    public static function forOutOfRangeMinConfidence(float $minConfidence): self
    {
        return new self(\sprintf('minConfidence must be finite and within 0.0-1.0, got %s', self::render($minConfidence)));
    }

    /**
     * PHP 8.5 emits a warning when a NAN/INF float is coerced to string (e.g.
     * through `sprintf('%s', ...)`), which the test suite's `failOnWarning`
     * turns into a failure. Rendering each non-finite case as an explicit
     * literal keeps the `(string)` cast on finite values only, so the message
     * stays identical without ever triggering the coercion.
     */
    private static function render(float $minConfidence): string
    {
        return match (true) {
            is_finite($minConfidence) => (string) $minConfidence,
            is_nan($minConfidence) => 'NAN',
            \INF === $minConfidence => 'INF',
            default => '-INF',
        };
    }
}
