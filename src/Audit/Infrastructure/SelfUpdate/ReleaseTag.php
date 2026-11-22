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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate;

/**
 * The only release tag shape the updater trusts: `X.Y.Z`, an optional SemVer
 * pre-release and an optional leading `v`. Anything else is refused, not
 * escaped: a tag goes into download URLs and the terminal.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReleaseTag
{
    private const string PATTERN = '/^[vV]?\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/D';

    public static function isValid(string $tag): bool
    {
        return 1 === preg_match(self::PATTERN, $tag);
    }
}
