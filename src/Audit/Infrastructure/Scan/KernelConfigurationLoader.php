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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProductionConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\UnreadableYamlException;

/**
 * The YAML configuration files a Symfony production kernel loads, in load
 * order: `config/packages/*.yaml`, then `config/packages/prod/`, each file
 * after the files it imports. The project's files come first, then apart those
 * of the monorepo application each `--path` lies in (the nearest folder
 * holding a `config/packages/`). Reads within per-file and total bounds and
 * reports an unread file that may hold security configuration with the reason.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 *
 * @phpstan-type Loading array{seen: array<string, string>, loaded: list<ProjectFile>, unreadable: array<string, string>, files: int, bytes: int}
 */
final readonly class KernelConfigurationLoader
{
    private const string PRODUCTION_PACKAGES = 'config/packages/prod/';

    private const int MAX_IMPORT_DEPTH = 8;

    private const int MAX_FILES = 128;

    private const int MAX_BYTES = 2_097_152;

    public function __construct(
        private YamlImportResolver $yamlImportResolver = new YamlImportResolver(),
        private RepositoryYamlReader $repositoryYamlReader = new RepositoryYamlReader(),
    ) {}

    /**
     * Whether the production kernel loads the file: a `.yaml` file of
     * `config/packages/`, `config/packages/security.yml` or a file under
     * `config/packages/prod/`.
     *
     * @param string $pathInApplication the file's path, relative to the application's root
     */
    public static function isLoadedByTheKernel(string $pathInApplication): bool
    {
        return 1 === preg_match('~\Aconfig/packages/(?:prod/.+\.ya?ml|security\.yml|[^/]+\.yaml)\z~', $pathInApplication);
    }

    /**
     * 0 for `config/packages/*.yaml`, 1 for `config/packages/prod/`, which the
     * kernel loads after.
     *
     * @param string $pathInApplication the file's path, relative to the application's root
     */
    public static function loadRank(string $pathInApplication): int
    {
        return str_starts_with($pathInApplication, self::PRODUCTION_PACKAGES) ? 1 : 0;
    }

    /**
     * @param list<ProjectFile> $files
     * @param list<string>      $scanPaths the run's `--path` values, normalized
     */
    public function filesInLoadOrder(array $files, array $scanPaths): ProductionConfiguration
    {
        $yamlFiles = $this->yamlFilesInPathOrder($files);
        $yamlFilesByFolder = $this->yamlFilesByFolder($yamlFiles);
        $loading = $this->applicationFiles('', $yamlFiles, $yamlFilesByFolder, ['seen' => [], 'loaded' => [], 'unreadable' => [], 'files' => 0, 'bytes' => 0]);
        $projectFiles = $loading['loaded'];
        $applicationFiles = [];
        foreach ($this->applicationFolders($yamlFiles, $scanPaths) as $applicationFolder) {
            $loading = $this->applicationFiles($applicationFolder, $yamlFiles, $yamlFilesByFolder, $loading);
            $applicationFiles[$applicationFolder] = $loading['loaded'];
        }

        return new ProductionConfiguration($projectFiles, $applicationFiles, $loading['unreadable']);
    }

    /**
     * Each application reads its own files, shared ones included, within the
     * run's budget.
     *
     * @param list<ProjectFile>                $yamlFiles
     * @param array<string, list<ProjectFile>> $yamlFilesByFolder
     * @param Loading                          $loading
     *
     * @return Loading
     */
    private function applicationFiles(string $applicationFolder, array $yamlFiles, array $yamlFilesByFolder, array $loading): array
    {
        $loading['seen'] = [];
        $loading['loaded'] = [];
        foreach ($this->entryFiles($yamlFiles, $applicationFolder) as $projectFile) {
            $loading = $this->load($projectFile, $yamlFilesByFolder, 0, $loading);
        }

        return $loading;
    }

    /**
     * @param list<ProjectFile> $yamlFiles
     * @param list<string>      $scanPaths
     *
     * @return array<string, string> the folder of the application each scan path lies in, each ending with a `/`, once
     */
    private function applicationFolders(array $yamlFiles, array $scanPaths): array
    {
        $applicationFolders = [];
        foreach ($scanPaths as $scanPath) {
            foreach ($this->nearestApplicationFolder($scanPath, $yamlFiles) as $applicationFolder) {
                $applicationFolders[$applicationFolder] = $applicationFolder;
            }
        }

        return $applicationFolders;
    }

    /**
     * @param list<ProjectFile> $yamlFiles
     *
     * @return list<string> the folder, or none when the path lies in no application of its own
     */
    private function nearestApplicationFolder(string $scanPath, array $yamlFiles): array
    {
        $applicationFolders = array_filter(
            array_reverse($this->foldersAlong($scanPath)),
            fn (string $folder): bool => [] !== $this->entryFiles($yamlFiles, $folder),
        );

        return \array_slice($applicationFolders, 0, 1);
    }

    /**
     * @return list<string> `apps/`, `apps/api/` for `apps/api`
     */
    private function foldersAlong(string $scanPath): array
    {
        $folders = [];
        $folder = '';
        foreach (explode('/', $scanPath) as $segment) {
            $folder = \sprintf('%s%s/', $folder, $segment);
            $folders[] = $folder;
        }

        return $folders;
    }

    /**
     * @param array<string, list<ProjectFile>> $yamlFilesByFolder
     * @param Loading                          $loading
     *
     * @return Loading
     */
    private function load(ProjectFile $projectFile, array $yamlFilesByFolder, int $depth, array $loading): array
    {
        $path = $projectFile->relativePath();
        if (\array_key_exists($path, $loading['seen'])) {
            return $loading;
        }

        $loading['seen'][$path] = $path;
        try {
            $importedFiles = $this->importedFilesOf($projectFile, $yamlFilesByFolder, $depth, $loading);
        } catch (UnreadableYamlException $unreadableYamlException) {
            return $this->withUnreadable($projectFile, $unreadableYamlException, $loading);
        }

        ++$loading['files'];
        $loading['bytes'] += \strlen($projectFile->content());
        foreach ($importedFiles as $importedFile) {
            $loading = $this->load($importedFile, $yamlFilesByFolder, $depth + 1, $loading);
        }

        $loading['loaded'][] = $projectFile;

        return $loading;
    }

    /**
     * Reports an unreadable file only when a top-level key of it holds or
     * imports security configuration.
     *
     * @param Loading $loading
     *
     * @return Loading
     */
    private function withUnreadable(ProjectFile $projectFile, UnreadableYamlException $unreadableYamlException, array $loading): array
    {
        if (1 === preg_match('~^(?:security|when@prod|imports|access_control|firewalls)[ \t]*:~m', $projectFile->content())) {
            $loading['unreadable'][$projectFile->relativePath()] = $unreadableYamlException->getMessage();
        }

        return $loading;
    }

    /**
     * @param array<string, list<ProjectFile>> $yamlFilesByFolder
     * @param Loading                          $loading
     *
     * @return list<ProjectFile>
     *
     * @throws UnreadableYamlException
     */
    private function importedFilesOf(ProjectFile $projectFile, array $yamlFilesByFolder, int $depth, array $loading): array
    {
        $this->assertWithinBudget($projectFile, $depth, $loading);

        return $this->yamlImportResolver->importedFiles(
            $projectFile,
            $this->repositoryYamlReader->read($projectFile->content()),
            static fn (string $folder): array => $yamlFilesByFolder[$folder] ?? [],
        );
    }

    /**
     * @param Loading $loading
     *
     * @throws UnreadableYamlException
     */
    private function assertWithinBudget(ProjectFile $projectFile, int $depth, array $loading): void
    {
        if (self::MAX_IMPORT_DEPTH < $depth) {
            throw UnreadableYamlException::importedTooDeep(self::MAX_IMPORT_DEPTH);
        }

        if (self::MAX_FILES <= $loading['files']) {
            throw UnreadableYamlException::beyondFileBudget(self::MAX_FILES);
        }

        if (self::MAX_BYTES < $loading['bytes'] + \strlen($projectFile->content())) {
            throw UnreadableYamlException::beyondByteBudget(self::MAX_BYTES);
        }
    }

    /**
     * @param list<ProjectFile> $yamlFiles
     *
     * @return list<ProjectFile>
     */
    private function entryFiles(array $yamlFiles, string $applicationFolder): array
    {
        $entryFiles = array_filter(
            $yamlFiles,
            static fn (ProjectFile $projectFile): bool => str_starts_with($projectFile->relativePath(), $applicationFolder) && self::isLoadedByTheKernel(self::pathInApplication($projectFile, $applicationFolder)),
        );
        usort($entryFiles, static fn (ProjectFile $left, ProjectFile $right): int => self::loadRank(self::pathInApplication($left, $applicationFolder)) <=> self::loadRank(self::pathInApplication($right, $applicationFolder)));

        return $entryFiles;
    }

    private static function pathInApplication(ProjectFile $projectFile, string $applicationFolder): string
    {
        return substr($projectFile->relativePath(), \strlen($applicationFolder));
    }

    /**
     * @param list<ProjectFile> $yamlFiles
     *
     * @return array<string, list<ProjectFile>> the files directly in each folder, in path order
     */
    private function yamlFilesByFolder(array $yamlFiles): array
    {
        $yamlFilesByFolder = [];
        foreach ($yamlFiles as $yamlFile) {
            $yamlFilesByFolder[Path::getDirectory($yamlFile->relativePath())][] = $yamlFile;
        }

        return $yamlFilesByFolder;
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    private function yamlFilesInPathOrder(array $files): array
    {
        $yamlFiles = array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => 1 === preg_match('~\.ya?ml\z~', $projectFile->relativePath()),
        );
        usort($yamlFiles, static fn (ProjectFile $left, ProjectFile $right): int => strcmp($left->relativePath(), $right->relativePath()));

        return $yamlFiles;
    }
}
