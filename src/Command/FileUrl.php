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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use function Symfony\Component\String\u;

/**
 * A local path written as the `file://` URL a browser or a terminal opens.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FileUrl
{
    private const string WINDOWS_DRIVE = '/^([A-Za-z])%3A(?=\/|$)/';

    public static function of(string $path): string
    {
        $encodedPath = implode('/', array_map(rawurlencode(...), explode('/', u($path)->replace('\\', '/')->toString())));
        $withDriveLetter = preg_replace(self::WINDOWS_DRIVE, '$1:', $encodedPath) ?? $encodedPath;

        return u($withDriveLetter)->ensureStart('/')->prepend('file://')->toString();
    }
}
