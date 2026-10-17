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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat;

/**
 * The pull requests, as `#123`, that the `CHANGELOG.md` bullets under
 * `## [Unreleased]` link: a difference from the last release is accepted only
 * when the release about to ship announces it, not when an older release
 * happened to word it.
 */
final readonly class UnreleasedChangelog
{
    private const string CHANGELOG = __DIR__.'/../../../CHANGELOG.md';

    /**
     * @return list<string>
     */
    public static function references(): array
    {
        $section = 1 === preg_match('/^## \[Unreleased\]\R(.*?)(?=^## \[)/ms', (string) file_get_contents(self::CHANGELOG), $match) ? $match[1] : '';
        preg_match_all('/\[#(\d+)\]\(https:\/\/github\.com\/[^\/)]+\/[^\/)]+\/pull\/\1\)/', $section, $links);

        return array_values(array_unique(array_map(static fn (string $number): string => '#'.$number, $links[1])));
    }

    public static function announces(string $reference): bool
    {
        return \in_array($reference, self::references(), true);
    }
}
