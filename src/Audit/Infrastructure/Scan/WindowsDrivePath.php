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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Symfony\Component\Filesystem\Path;

use function Symfony\Component\String\u;

/**
 * The one spelling of a Windows drive path (`C:\proj`, `c:/proj`, the
 * `/C:/proj` a `file:///C:/proj` URI leaves behind) every runtime compares by:
 * forward slashes, an upper-case drive letter, no dot segments. {@see Path}
 * reads such a path only on Windows, so a SARIF report written there and
 * audited anywhere else needs this to match the project root. Any other path
 * comes back as it was, since a backslash is a valid file name character on
 * UNIX.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class WindowsDrivePath
{
    private const string DRIVE_PREFIX_PATTERN = '#^/?[A-Za-z]:[/\\\\]#';

    public static function normalize(string $path): string
    {
        if (1 !== preg_match(self::DRIVE_PREFIX_PATTERN, $path)) {
            return $path;
        }

        return Path::canonicalize(u($path)->replace('\\', '/')->trimStart('/')->title()->toString());
    }
}
