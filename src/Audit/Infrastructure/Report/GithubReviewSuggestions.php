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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

/**
 * The review comments the GitHub Action posts as one review, hidden in a
 * `github-comment` body as a base64 JSON list, so no text of it can close
 * the HTML comment around it. The list stops before the comment outgrows
 * what GitHub accepts.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class GithubReviewSuggestions
{
    public const string MARKER_PREFIX = '<!-- symfony-security-auditor:review-suggestions:';

    private const string MARKER_SUFFIX = ' -->';

    private const int MAXIMUM_ENCODED_LENGTH = 40_000;

    /**
     * Returns no block longer than `$maximumLength` characters.
     *
     * @param list<GithubSuggestion> $githubSuggestions
     */
    public static function block(array $githubSuggestions, ReportPathPrefix $reportPathPrefix, int $maximumLength = \PHP_INT_MAX): ?string
    {
        $maximumEncodedLength = min(self::MAXIMUM_ENCODED_LENGTH, $maximumLength - \strlen(self::MARKER_PREFIX) - \strlen(self::MARKER_SUFFIX));
        $reviewComments = [];
        $encoded = '';
        foreach ($githubSuggestions as $githubSuggestion) {
            $candidate = base64_encode(json_encode([...$reviewComments, $githubSuggestion->reviewComment($reportPathPrefix)], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
            if (\strlen($candidate) > $maximumEncodedLength) {
                break;
            }

            $reviewComments[] = $githubSuggestion->reviewComment($reportPathPrefix);
            $encoded = $candidate;
        }

        return '' === $encoded ? null : \sprintf('%s%s%s', self::MARKER_PREFIX, $encoded, self::MARKER_SUFFIX);
    }
}
