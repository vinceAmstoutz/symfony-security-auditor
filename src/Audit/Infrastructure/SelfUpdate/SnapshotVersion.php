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
 * The version a snapshot binary is stamped with: the last release, the number
 * of commits after it and the commit, as SemVer build metadata
 * (`1.21.0+14.g4531440`). Anything else is refused: it is printed to the
 * terminal.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SnapshotVersion
{
    private const string PATTERN = '/^\d+\.\d+\.\d+\+\d+\.g[0-9a-f]{7,40}$/D';

    public static function isValid(string $version): bool
    {
        return 1 === preg_match(self::PATTERN, $version);
    }
}
