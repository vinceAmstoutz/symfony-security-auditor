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

use Closure;
use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;

/**
 * The project a run audits and the paths it narrows to, as the command line
 * names them. A directory holding no `composer.json` and no file the scan
 * reaches is not a project, and a scan of it would find nothing: the run
 * audits the Composer project the named paths lie in instead, narrowed to
 * them, so `audit app/src` audits what `audit app --path src` does.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditTarget
{
    private const string COMPOSER_FILE = 'composer.json';

    /**
     * @param list<string> $scanPaths
     * @param ?string      $folder    the directory named, when it is not the project but a folder the project encloses
     */
    private function __construct(
        public string $projectPath,
        public array $scanPaths,
        public ?string $folder = null,
    ) {}

    /**
     * @param string                 $directory      the project path the command line names, absolute
     * @param list<string>           $scanPaths      the `--path` values as given
     * @param ?Closure(string): bool $holdsScanFiles whether the configured scan finds a file in a directory, which makes it the project an earlier release audited; none asks whether a path `scan.included_paths` lists by default exists in it
     */
    public static function named(string $directory, array $scanPaths, ?Closure $holdsScanFiles = null): self
    {
        if (!is_dir($directory) || is_file(Path::join($directory, self::COMPOSER_FILE)) || ($holdsScanFiles ?? self::holdsDefaultScanPaths(...))($directory)) {
            return new self($directory, $scanPaths);
        }

        $targets = [] === $scanPaths ? [$directory] : array_map(static fn (string $scanPath): string => Path::makeAbsolute($scanPath, $directory), $scanPaths);
        $project = self::enclosingProjectOf($targets);

        return null === $project ? new self($directory, $scanPaths) : new self($project, $targets, $directory);
    }

    private static function holdsDefaultScanPaths(string $directory): bool
    {
        foreach (ProjectFileScanner::DEFAULT_INCLUDED_PATHS as $includedPath) {
            if (file_exists(Path::join($directory, $includedPath))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param non-empty-list<string> $targets
     */
    private static function enclosingProjectOf(array $targets): ?string
    {
        $projects = array_unique(array_map(self::enclosingProject(...), $targets));

        return 1 === \count($projects) ? reset($projects) : null;
    }

    private static function enclosingProject(string $path): ?string
    {
        $directory = $path;
        while (!is_file(Path::join($directory, self::COMPOSER_FILE))) {
            $parent = Path::getDirectory($directory);
            if ($parent === $directory) {
                return null;
            }

            $directory = $parent;
        }

        return $directory;
    }
}
