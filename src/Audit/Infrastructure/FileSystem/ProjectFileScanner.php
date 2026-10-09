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

use Closure;
use FilesystemIterator;
use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;
use Throwable;
use UnexpectedValueException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFileReason;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ScopedProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SkippedFileReportingProjectFileScannerInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ProjectFileScanner implements ScopedProjectFileScannerInterface, SkippedFileReportingProjectFileScannerInterface
{
    /** @var list<string> */
    private const array PHP_EXTENSIONS = ['php'];

    /** @var list<string> */
    private const array TEMPLATE_EXTENSIONS = ['twig'];

    /** @var list<string> */
    private const array CONFIG_EXTENSIONS = ['yaml', 'yml', 'xml'];

    public const int DEFAULT_MAX_FILE_SIZE_KB = 512;

    /**
     * Default allow-list of project-relative paths scanned for security
     * findings. Matches the Symfony Flex skeleton (`src/` for PHP, `config/`
     * for YAML/XML, `templates/` for Twig, `public/index.php` for the HTTP
     * front controller, plus the root dotenv files where committed secrets
     * hide — the gitignored `.env.local` variants are pruned by the default
     * `respect_gitignore: true`). Anything outside this list is silently
     * skipped — including ad-hoc root-level scripts, `bin/`, custom `app/`
     * or `lib/` trees, and the build artefacts in `var/`, `public/build`,
     * `vendor/`. Override via `scan.included_paths` for non-standard layouts.
     *
     * @var list<string>
     */
    public const array DEFAULT_INCLUDED_PATHS = [
        'src',
        'config',
        'templates',
        'public/index.php',
        '.env',
        '.env.local',
        '.env.dev',
        '.env.test',
        '.env.prod',
        '.env.dist',
    ];

    /**
     * @param list<string>                  $includedPaths project-relative directories and files to scan; defaults to the Symfony skeleton layout
     * @param ?Closure(SplFileInfo): string $fileReader    defaults to SplFileInfo::getContents; tests inject a stub
     */
    public function __construct(
        private LoggerInterface $logger,
        private array $includedPaths = self::DEFAULT_INCLUDED_PATHS,
        private bool $respectGitignore = false,
        private int $maxFileSizeKb = self::DEFAULT_MAX_FILE_SIZE_KB,
        private ?Closure $fileReader = null,
        private ?SecretScrubberInterface $secretScrubber = null,
    ) {}

    /**
     * @return list<ProjectFile>
     */
    #[Override]
    public function scan(string $projectPath): array
    {
        return $this->scanReportingSkippedFiles($projectPath)->files;
    }

    /**
     * @param non-empty-list<string> $scanPaths
     *
     * @return list<ProjectFile>
     */
    #[Override]
    public function scanWithin(string $projectPath, array $scanPaths): array
    {
        return $this->scanReportingSkippedFiles($projectPath, $scanPaths)->files;
    }

    /**
     * @param list<string> $scanPaths project-relative paths that replace the configured ones; none scans the configured ones
     */
    #[Override]
    public function scanReportingSkippedFiles(string $projectPath, array $scanPaths = []): ProjectFileScan
    {
        if ([] === $scanPaths) {
            return $this->scanRoots($projectPath, $this->includedPaths, 'No included paths exist in project', ['included_paths' => $this->includedPaths, 'project_path' => $projectPath]);
        }

        return $this->scanRoots($projectPath, $scanPaths, 'No scan paths exist in project', ['scan_paths' => $scanPaths, 'project_path' => $projectPath]);
    }

    /**
     * @param list<string>         $roots          project-relative directories and files to scan
     * @param array<string, mixed> $noRootsContext what the warning says when none of the roots exists
     */
    private function scanRoots(string $projectPath, array $roots, string $noRootsMessage, array $noRootsContext): ProjectFileScan
    {
        $this->logger->info('Scanning project', ['path' => $projectPath]);

        [$directories, $explicitFiles] = $this->resolveRoots($projectPath, $roots);

        if ([] === $directories && [] === $explicitFiles) {
            $this->logger->warning($noRootsMessage, $noRootsContext);

            return new ProjectFileScan([], []);
        }

        $reader = $this->fileReader ?? static fn (SplFileInfo $splFile): string => $splFile->getContents();

        $directoryScan = $this->scanDirectories($directories, $projectPath, $reader);
        $explicitFileScan = $this->scanExplicitFiles($explicitFiles, $projectPath, $reader);

        $projectFileScan = $this->inRelativePathOrder($this->eachFileOnce(new ProjectFileScan(
            array_merge($directoryScan->files, $explicitFileScan->files),
            array_merge($directoryScan->skippedFiles, $explicitFileScan->skippedFiles),
        )));

        $this->logger->info('Scan complete', ['files' => \count($projectFileScan->files)]);

        return $projectFileScan;
    }

    /**
     * Paths that overlap — a directory and one inside it, a directory and a
     * file in it — reach the same file more than once.
     */
    private function eachFileOnce(ProjectFileScan $projectFileScan): ProjectFileScan
    {
        $files = [];
        $sharingAName = [];
        foreach ($this->eachRealFileOnce($projectFileScan->files) as $projectFile) {
            if (\array_key_exists($projectFile->relativePath(), $files)) {
                $sharingAName[] = new SkippedFile($projectFile->relativePath(), SkippedFileReason::AmbiguousName);

                continue;
            }

            $files[$projectFile->relativePath()] = $projectFile;
        }

        $skippedFiles = [];
        foreach ([...$projectFileScan->skippedFiles, ...$sharingAName] as $skippedFile) {
            $skippedFiles[$skippedFile->relativePath] ??= $skippedFile;
        }

        return new ProjectFileScan(array_values($files), array_values($skippedFiles));
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile> in byte order of their absolute path
     */
    private function eachRealFileOnce(array $files): array
    {
        $byRealPath = [];
        foreach ($files as $file) {
            $byRealPath[Path::canonicalize($file->absolutePath())] ??= $file;
        }

        ksort($byRealPath, \SORT_STRING);

        return array_values($byRealPath);
    }

    /**
     * A filesystem lists a directory in its own storage order, which differs
     * between machines; the chunks built from this list, and the prompts and
     * cache keys built from those, must not.
     */
    private function inRelativePathOrder(ProjectFileScan $projectFileScan): ProjectFileScan
    {
        $files = $projectFileScan->files;
        usort($files, static fn (ProjectFile $left, ProjectFile $right): int => strcmp($left->relativePath(), $right->relativePath()));

        $skippedFiles = $projectFileScan->skippedFiles;
        usort($skippedFiles, static fn (SkippedFile $left, SkippedFile $right): int => strcmp($left->relativePath, $right->relativePath));

        return new ProjectFileScan($files, $skippedFiles);
    }

    /**
     * @param list<string>                 $directories
     * @param Closure(SplFileInfo): string $reader
     */
    private function scanDirectories(array $directories, string $projectPath, Closure $reader): ProjectFileScan
    {
        if ([] === $directories) {
            return new ProjectFileScan([], []);
        }

        $finder = (new Finder())
            ->files()
            ->in($directories)
            ->name($this->finderNamePatterns())
            ->filter($this->entersReadableDirectory(...), true);

        return $this->collectFilesFrom($finder, $projectPath, $reader);
    }

    private function entersReadableDirectory(SplFileInfo $splFile): bool
    {
        if (!$splFile->isDir()) {
            return true;
        }

        try {
            new FilesystemIterator($splFile->getPathname());
        } catch (UnexpectedValueException $unexpectedValueException) {
            $this->logger->warning('Skipped unreadable directory', [
                'path' => $splFile->getPathname(),
                'error' => $unexpectedValueException->getMessage(),
            ]);

            return false;
        }

        return true;
    }

    /**
     * @param list<string>                 $explicitFiles
     * @param Closure(SplFileInfo): string $reader
     */
    private function scanExplicitFiles(array $explicitFiles, string $projectPath, Closure $reader): ProjectFileScan
    {
        $files = [];
        $skippedFiles = [];
        foreach ($explicitFiles as $explicitFile) {
            $explicitFinder = (new Finder())
                ->files()
                ->ignoreDotFiles(false)
                ->in(\dirname($explicitFile))
                ->depth('== 0')
                ->name(basename($explicitFile));

            $explicitFileScan = $this->collectFilesFrom($explicitFinder, $projectPath, $reader);
            $files = array_merge($files, $explicitFileScan->files);
            $skippedFiles = array_merge($skippedFiles, $explicitFileScan->skippedFiles);
        }

        return new ProjectFileScan($files, $skippedFiles);
    }

    /**
     * @param Closure(SplFileInfo): string $reader
     */
    private function collectFilesFrom(Finder $finder, string $projectPath, Closure $reader): ProjectFileScan
    {
        if ($this->respectGitignore) {
            $finder->ignoreVCSIgnored(true);
        }

        $files = [];
        $skippedFiles = [];
        /** @var SplFileInfo $splFile */
        foreach ($finder as $splFile) {
            $outcome = $this->scanFile($splFile, $projectPath, $reader);
            if ($outcome instanceof ProjectFile) {
                $files[] = $outcome;
            }

            if ($outcome instanceof SkippedFile) {
                $skippedFiles[] = $outcome;
            }
        }

        return new ProjectFileScan($files, $skippedFiles);
    }

    /**
     * @return list<string>
     */
    private function finderNamePatterns(): array
    {
        return array_merge(
            array_map(static fn (string $ext): string => \sprintf('*.%s', $ext), self::PHP_EXTENSIONS),
            array_map(static fn (string $ext): string => \sprintf('*.%s', $ext), self::TEMPLATE_EXTENSIONS),
            array_map(static fn (string $ext): string => \sprintf('*.%s', $ext), self::CONFIG_EXTENSIONS),
        );
    }

    /**
     * Containment is decided on real paths, not on spellings: a symlink
     * committed in the audited repository can point anywhere on the machine,
     * and a lexical check would call `src/link/` or `src/link/deep/..` part of
     * the project while the filesystem walks into the link's target.
     *
     * @param list<string> $roots
     *
     * @return array{0: list<string>, 1: list<string>}
     */
    private function resolveRoots(string $projectPath, array $roots): array
    {
        $realProjectPath = realpath($projectPath);
        if (false === $realProjectPath) {
            return [[], []];
        }

        return $this->partitionDirectoriesAndFiles($this->scannableRoots($projectPath, $realProjectPath, $roots));
    }

    /**
     * @param list<string> $roots
     *
     * @return list<string>
     */
    private function scannableRoots(string $projectPath, string $realProjectPath, array $roots): array
    {
        $scannable = [];
        foreach ($roots as $root) {
            $resolved = $projectPath.\DIRECTORY_SEPARATOR.$root;
            if ($this->isScannable($resolved, $realProjectPath)) {
                $scannable[] = $resolved;
            }
        }

        return $scannable;
    }

    /**
     * @param list<string> $paths
     *
     * @return array{0: list<string>, 1: list<string>}
     */
    private function partitionDirectoriesAndFiles(array $paths): array
    {
        $directories = [];
        $explicitFiles = [];
        foreach ($paths as $path) {
            if (is_dir($path)) {
                $directories[] = $path;

                continue;
            }

            if (is_file($path)) {
                $explicitFiles[] = $path;
            }
        }

        return [$this->outermost($directories), $explicitFiles];
    }

    /**
     * A directory listed inside another is already walked by it, so it is left
     * out rather than read and scrubbed a second time.
     *
     * @param list<string> $directories
     *
     * @return list<string>
     */
    private function outermost(array $directories): array
    {
        $unique = array_unique(array_map(Path::canonicalize(...), $directories));

        return array_values(array_filter(
            $unique,
            static fn (string $directory): bool => [] === array_filter(
                $unique,
                static fn (string $other): bool => $other !== $directory && Path::isBasePath($other, $directory),
            ),
        ));
    }

    private function isScannable(string $resolved, string $realProjectPath): bool
    {
        if (is_link($resolved)) {
            $this->logger->warning('Skipped symlinked included path', ['path' => $resolved]);

            return false;
        }

        $realResolved = realpath($resolved);

        return false !== $realResolved && $this->isInsideProject($resolved, $realResolved, $realProjectPath);
    }

    private function isInsideProject(string $resolved, string $realResolved, string $realProjectPath): bool
    {
        if (Path::isBasePath($realProjectPath, $realResolved)) {
            return true;
        }

        $this->logger->warning('Skipped included path outside the project root', ['path' => $resolved]);

        return false;
    }

    /**
     * @param Closure(SplFileInfo): string $reader
     */
    private function scanFile(SplFileInfo $splFile, string $projectPath, Closure $reader): ProjectFile|SkippedFile|null
    {
        if ($splFile->isLink()) {
            $this->logger->warning('Skipped symlinked file', ['path' => $splFile->getPathname()]);

            return null;
        }

        $relativePath = $this->validUtf8RelativePath($splFile, $projectPath);

        try {
            if ($splFile->getSize() > $this->maxFileSizeKb * 1024) {
                return new SkippedFile($relativePath, SkippedFileReason::TooLarge);
            }

            $content = $reader($splFile);
            if ($this->secretScrubber instanceof SecretScrubberInterface) {
                $content = $this->secretScrubber->scrub($content);
            }

            return ProjectFile::create(
                relativePath: $relativePath,
                absolutePath: $splFile->getPathname(),
                content: $this->validUtf8Content($content, $relativePath),
            );
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to read file', [
                'path' => $splFile->getPathname(),
                'error' => $throwable->getMessage(),
            ]);

            return new SkippedFile($relativePath, SkippedFileReason::Unreadable);
        }
    }

    private function validUtf8RelativePath(SplFileInfo $splFile, string $projectPath): string
    {
        $relativePath = Path::makeRelative($splFile->getPathname(), $projectPath);
        $valid = Utf8Normalizer::normalize($relativePath);
        if ($valid !== $relativePath) {
            $this->logger->warning('File name is not valid UTF-8, its invalid bytes were replaced', ['path' => $valid]);
        }

        return $valid;
    }

    private function validUtf8Content(string $content, string $relativePath): string
    {
        $valid = Utf8Normalizer::normalize($content);
        if ($valid !== $content) {
            $this->logger->warning('File content is not valid UTF-8, its invalid bytes were replaced', ['path' => $relativePath]);
        }

        return $valid;
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    public function filterByType(array $files, string $type): array
    {
        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => $projectFile->type() === $type,
        ));
    }

    /**
     * @param list<ProjectFile> $files
     */
    public function buildContext(array $files): string
    {
        $lines = [];
        foreach ($files as $file) {
            $lines[] = \sprintf(
                "=== FILE: %s (%s, %d lines) ===\n%s\n",
                $file->relativePath(),
                $file->type(),
                $file->linesCount(),
                $file->content(),
            );
        }

        return implode("\n", $lines);
    }
}
