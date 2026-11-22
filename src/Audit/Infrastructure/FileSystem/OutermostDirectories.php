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

use Symfony\Component\Filesystem\Path;

/**
 * The listed directories that no other listed directory holds, as
 * {@see Path::isBasePath()} decides, each once and in list order.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class OutermostDirectories
{
    /**
     * @param list<string> $directories
     *
     * @return list<string> canonical paths
     */
    public static function of(array $directories): array
    {
        $unique = array_unique(array_map(Path::canonicalize(...), $directories));

        $listedUnder = [];
        foreach ($unique as $directory) {
            $listedUnder[\sprintf('%s/', rtrim($directory, '/'))][] = $directory;
        }

        return array_values(array_filter($unique, static fn (string $directory): bool => !self::liesInsideAnother($directory, $listedUnder)));
    }

    /**
     * @param array<string, list<string>> $listedUnder the listed directories, by the path every directory inside them starts with
     */
    private static function liesInsideAnother(string $directory, array $listedUnder): bool
    {
        $parentPath = '';
        foreach (explode('/', $directory) as $segment) {
            $parentPath .= \sprintf('%s/', $segment);
            if ([] !== array_diff($listedUnder[$parentPath] ?? [], [$directory])) {
                return true;
            }
        }

        return false;
    }
}
