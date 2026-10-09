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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

/**
 * `preg_replace_callback()` that hands the callback where each group sits in the content.
 *
 * The callback of `preg_replace_callback()` receives the text of a match, not its position, and
 * its `PREG_OFFSET_CAPTURE` flag changes the shape of what the callback receives in a way static
 * analysis does not follow.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class OffsetCaptureReplacer
{
    /**
     * @param callable(array<int|string, array{0: string, 1: int}>): string $replacement given each match as its groups, each a `[text, offset]` pair
     *
     * @return string|null null when the PCRE engine refuses to evaluate the pattern
     */
    public function replace(string $pattern, string $content, callable $replacement): ?string
    {
        if (false === preg_match_all($pattern, $content, $matches, \PREG_SET_ORDER | \PREG_OFFSET_CAPTURE)) {
            return null;
        }

        $replaced = '';
        $cursor = 0;
        foreach ($matches as $match) {
            $replaced .= substr($content, $cursor, $match[0][1] - $cursor).$replacement($match);
            $cursor = $match[0][1] + \strlen($match[0][0]);
        }

        return $replaced.substr($content, $cursor);
    }
}
