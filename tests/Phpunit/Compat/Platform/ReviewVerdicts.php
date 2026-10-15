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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform;

/**
 * The scripted reviewer: it reads the part of the prompt that describes a
 * finding and accepts it, unless the title says REJECT, DOWNGRADE or UPGRADE,
 * or the script holds a verdict for a fragment of that part.
 */
final readonly class ReviewVerdicts
{
    private const int WINDOW = 1500;

    private const string FILE_CONTEXT_HEADING = '## Full File Context';

    /**
     * @return array<string, mixed>
     */
    public static function verdictFor(string $findingId, string $prompt): array
    {
        $window = self::windowOf($findingId, $prompt);
        $platformScript = PlatformSession::script();

        foreach ($platformScript->reviewerSequences as $fragment => $verdicts) {
            if (str_contains($window, $fragment)) {
                $review = PlatformSession::nextReviewOf($fragment);

                return ['id' => $findingId] + $verdicts[min($review, \count($verdicts)) - 1] + ['accepted' => true];
            }
        }

        foreach ($platformScript->reviewerVerdicts as $fragment => $verdict) {
            if (str_contains($window, $fragment)) {
                return ['id' => $findingId] + $verdict;
            }
        }

        return ['id' => $findingId] + self::keywordVerdict($window);
    }

    /**
     * @return array<string, mixed>
     */
    private static function keywordVerdict(string $window): array
    {
        return match (true) {
            str_contains($window, 'REJECT') => ['accepted' => false, 'reviewer_notes' => 'Not exploitable'],
            str_contains($window, 'DOWNGRADE') => ['accepted' => true, 'reviewer_notes' => 'Confirmed', 'adjusted_severity' => 'low'],
            str_contains($window, 'UPGRADE') => ['accepted' => true, 'reviewer_notes' => 'Confirmed', 'adjusted_severity' => 'critical'],
            default => ['accepted' => true, 'reviewer_notes' => 'Confirmed'],
        };
    }

    private static function windowOf(string $findingId, string $prompt): string
    {
        $position = strpos($prompt, $findingId);
        $window = substr($prompt, false === $position ? 0 : $position, self::WINDOW);
        $cut = strpos($window, self::FILE_CONTEXT_HEADING);

        return false === $cut ? $window : substr($window, 0, $cut);
    }
}
