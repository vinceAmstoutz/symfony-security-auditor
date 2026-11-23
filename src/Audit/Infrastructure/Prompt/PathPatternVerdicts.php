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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt;

/**
 * Whether an `access_control` path pattern, a regular expression, matches
 * each of several route paths, compiled once for all of them. A malformed
 * pattern, or one holding every delimiter candidate, matches nothing.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PathPatternVerdicts
{
    private const string DELIMITER_CANDIDATES = '#~!%@';

    private const int PATTERN_BACKTRACK_LIMIT = 10_000;

    /**
     * @param array<int, string> $routePaths
     *
     * @return array<int, ?bool> by the key of each path; null when the pattern cannot be decided for it
     */
    public static function of(string $pattern, array $routePaths): array
    {
        $delimiter = self::delimiterAvoiding($pattern);

        return null === $delimiter ? array_map(static fn (): bool => false, $routePaths) : self::matchEach($delimiter.$pattern.$delimiter, $routePaths);
    }

    /**
     * Captures the warning of a pattern that does not compile, which then
     * matches nothing. A match gets {@see self::PATTERN_BACKTRACK_LIMIT} steps
     * and is null when it cannot be decided within them.
     *
     * @param array<int, string> $routePaths
     *
     * @return array<int, ?bool>
     */
    private static function matchEach(string $delimitedPattern, array $routePaths): array
    {
        $compilationError = null;
        set_error_handler(static function (int $severity, string $message) use (&$compilationError): bool {
            $compilationError = $message;

            return true;
        });

        $backtrackLimit = ini_set('pcre.backtrack_limit', self::PATTERN_BACKTRACK_LIMIT);

        $verdicts = array_map(static function (string $routePath) use ($delimitedPattern, &$compilationError): ?bool {
            $compilationError = null;

            return self::verdictOf(preg_match($delimitedPattern, $routePath), $compilationError);
        }, $routePaths);
        ini_set('pcre.backtrack_limit', $backtrackLimit);
        restore_error_handler();

        return $verdicts;
    }

    private static function verdictOf(int|false $matched, ?string $compilationError): ?bool
    {
        if (false !== $matched) {
            return 1 === $matched;
        }

        return null === $compilationError ? null : false;
    }

    /**
     * A PCRE delimiter absent from the pattern, null when it holds every
     * candidate.
     */
    private static function delimiterAvoiding(string $pattern): ?string
    {
        foreach (str_split(self::DELIMITER_CANDIDATES) as $candidate) {
            if (!str_contains($pattern, $candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}
