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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Symfony\Component\Filesystem\Path;

/**
 * Where the audited project's `composer.lock` is read from. The project is
 * untrusted, so a lockfile that is a symlink is followed only when it leads to
 * a regular file inside the project's own root, the way a monorepo or a
 * devcontainer shares one: a link out of the project (`/dev/zero`, a file of
 * the audit host) or to anything else than a regular file is refused.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LockfileSymlinkResolver
{
    /**
     * The path to read `$lockfilePath` from — itself, or the regular file
     * inside `$projectPath` it is a symlink to — or null when the symlink
     * leaves the project or does not lead to a regular file. The lockfile
     * must exist.
     */
    public static function resolve(string $lockfilePath, string $projectPath): ?string
    {
        if (!is_link($lockfilePath)) {
            return $lockfilePath;
        }

        $target = realpath($lockfilePath);
        $root = realpath($projectPath);
        \assert(false !== $target && false !== $root, 'realpath() must succeed for paths exists() already confirmed present');

        return is_file($target) && Path::isBasePath($root, $target) ? $target : null;
    }
}
