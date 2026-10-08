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
 * The only shape of release tag the updater trusts: `X.Y.Z`, optionally a
 * SemVer pre-release (`X.Y.Z-rc.1`) and optionally a leading `v`. A tag is
 * pasted into download URLs and printed to the terminal, so anything else —
 * a path, a query, a URL, a control character — is refused outright rather
 * than escaped.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReleaseTag
{
    private const string PATTERN = '/^[vV]?\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/D';

    public static function isValid(string $tag): bool
    {
        return 1 === preg_match(self::PATTERN, $tag);
    }
}
