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

use Closure;

/**
 * `preg_replace_callback()` that hands the callback the offset of each group.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
        return $this->replaceSharing($pattern, $content, static fn (): null => null, $replacement);
    }

    /**
     * {@see replace()} with a value worked out from the whole content: `$shared` runs once before
     * the first replacement and never when nothing matches.
     *
     * @template TShared
     *
     * @param Closure(): TShared                                                     $shared
     * @param callable(array<int|string, array{0: string, 1: int}>, TShared): string $replacement given each match as its groups (each a `[text, offset]` pair) and what `$shared` worked out
     *
     * @return string|null null when the PCRE engine refuses to evaluate the pattern
     */
    public function replaceSharing(string $pattern, string $content, Closure $shared, callable $replacement): ?string
    {
        if (false === preg_match_all($pattern, $content, $matches, \PREG_SET_ORDER | \PREG_OFFSET_CAPTURE)) {
            return null;
        }

        if ([] === $matches) {
            return $content;
        }

        $sharedValue = $shared();
        $replaced = '';
        $cursor = 0;
        foreach ($matches as $match) {
            $replaced .= substr($content, $cursor, $match[0][1] - $cursor).$replacement($match, $sharedValue);
            $cursor = $match[0][1] + \strlen($match[0][0]);
        }

        return $replaced.substr($content, $cursor);
    }
}
