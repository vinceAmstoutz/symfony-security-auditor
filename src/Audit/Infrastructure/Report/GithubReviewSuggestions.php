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
 * The review comments of a `github-comment` body, for the GitHub Action to
 * post as one pull-request review: a JSON list, base64-encoded so no text of
 * it can close the HTML comment that hides it. The list stops before it
 * would push the comment past what GitHub accepts.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GithubReviewSuggestions
{
    public const string MARKER_PREFIX = '<!-- symfony-security-auditor:review-suggestions:';

    private const int MAXIMUM_ENCODED_LENGTH = 40_000;

    /**
     * @param list<GithubSuggestion> $githubSuggestions
     */
    public static function block(array $githubSuggestions, ReportPathPrefix $reportPathPrefix): ?string
    {
        $reviewComments = [];
        $encoded = '';
        foreach ($githubSuggestions as $githubSuggestion) {
            $candidate = base64_encode(json_encode([...$reviewComments, $githubSuggestion->reviewComment($reportPathPrefix)], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE));
            if (\strlen($candidate) > self::MAXIMUM_ENCODED_LENGTH) {
                break;
            }

            $reviewComments[] = $githubSuggestion->reviewComment($reportPathPrefix);
            $encoded = $candidate;
        }

        return '' === $encoded ? null : \sprintf('%s%s -->', self::MARKER_PREFIX, $encoded);
    }
}
