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
 * Whether an `access_control` path pattern matches each of several route
 * paths, the paths matched one after the other so the pattern is compiled
 * once for all of them: PCRE keeps only the last 4,096 patterns it compiled,
 * so a list of rules longer than that, walked a route at a time, compiles
 * every pattern again for each route.
 *
 * Symfony treats the `access_control` `path` as a regular expression, so it
 * is matched as one; a malformed pattern, or one containing every delimiter
 * candidate, simply fails to match rather than throwing.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
     * `preg_match()` raises a warning for a pattern that does not compile
     * (`^/(admin`) and returns false; a warning-throwing error handler
     * (Symfony debug, `mcp:serve`) would abort the prompt build on a pattern
     * taken from the audited repository, so the warning is captured here and
     * the pattern simply matches nothing.
     *
     * A pattern from the repository may also backtrack catastrophically
     * (`^/(a+)+z$` against a long route path), and each route meets each
     * rule, so a match gets {@see self::PATTERN_BACKTRACK_LIMIT} steps rather
     * than `pcre.backtrack_limit`'s million. One it cannot decide within them
     * is null: the pattern may match the route, so it cannot be told.
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
     * Picks a PCRE delimiter guaranteed absent from the pattern, so the pattern
     * can never prematurely close or corrupt the delimited expression — unlike
     * a fixed delimiter (`#`, `{}`, …), which a sufficiently adversarial pattern
     * can always collide with.
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
