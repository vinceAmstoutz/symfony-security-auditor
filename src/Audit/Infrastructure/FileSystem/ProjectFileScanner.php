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
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ProjectFileScanner implements ProjectFileScannerInterface
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
     * front controller). Anything outside this list is silently skipped —
     * including ad-hoc root-level scripts, `bin/`, custom `app/` or `lib/`
     * trees, and the build artefacts in `var/`, `public/build`, `vendor/`.
     * Override via `scan.included_paths` for non-standard layouts.
     *
     * @var list<string>
     */
    public const array DEFAULT_INCLUDED_PATHS = ['src', 'config', 'templates', 'public/index.php'];

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
    public function scan(string $projectPath): array
    {
        $this->logger->info('Scanning project', ['path' => $projectPath]);

        [$directories, $explicitFiles] = $this->resolveIncludedPaths($projectPath);

        if ([] === $directories && [] === $explicitFiles) {
            $this->logger->warning('No included paths exist in project', [
                'included_paths' => $this->includedPaths,
                'project_path' => $projectPath,
            ]);

            return [];
        }

        $reader = $this->fileReader ?? static fn (SplFileInfo $splFile): string => $splFile->getContents();
        $files = [];

        if ([] !== $directories) {
            $extensions = array_merge(
                array_map(static fn (string $ext): string => '*.'.$ext, self::PHP_EXTENSIONS),
                array_map(static fn (string $ext): string => '*.'.$ext, self::TEMPLATE_EXTENSIONS),
                array_map(static fn (string $ext): string => '*.'.$ext, self::CONFIG_EXTENSIONS),
            );

            $finder = (new Finder())
                ->files()
                ->in($directories)
                ->name($extensions)
                ->size(\sprintf('<= %dK', $this->maxFileSizeKb));

            if ($this->respectGitignore) {
                $finder->ignoreVCSIgnored(true);
            }

            /** @var SplFileInfo $splFile */
            foreach ($finder as $splFile) {
                $file = $this->buildProjectFile($splFile, $projectPath, $reader);
                if ($file instanceof ProjectFile) {
                    $files[] = $file;
                }
            }
        }

        $maxBytes = $this->maxFileSizeKb * 1024;
        foreach ($explicitFiles as $explicitFile) {
            if (filesize($explicitFile) > $maxBytes) {
                continue;
            }

            $splFile = new SplFileInfo($explicitFile, '', basename($explicitFile));
            $file = $this->buildProjectFile($splFile, $projectPath, $reader);
            if ($file instanceof ProjectFile) {
                $files[] = $file;
            }
        }

        $this->logger->info('Scan complete', ['files' => \count($files)]);

        return $files;
    }

    /**
     * @return array{0: list<string>, 1: list<string>}
     */
    private function resolveIncludedPaths(string $projectPath): array
    {
        $directories = [];
        $explicitFiles = [];
        foreach ($this->includedPaths as $includedPath) {
            $resolved = $projectPath.\DIRECTORY_SEPARATOR.$includedPath;
            if (is_dir($resolved)) {
                $directories[] = $resolved;
            } elseif (is_file($resolved)) {
                $explicitFiles[] = $resolved;
            }
        }

        return [$directories, $explicitFiles];
    }

    /**
     * @param Closure(SplFileInfo): string $reader
     */
    private function buildProjectFile(SplFileInfo $splFile, string $projectPath, Closure $reader): ?ProjectFile
    {
        try {
            $content = $reader($splFile);
            if ($this->secretScrubber instanceof SecretScrubberInterface) {
                $content = $this->secretScrubber->scrub($content);
            }

            return ProjectFile::create(
                relativePath: Path::makeRelative($splFile->getPathname(), $projectPath),
                absolutePath: $splFile->getPathname(),
                content: $content,
            );
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to read file', [
                'path' => $splFile->getPathname(),
                'error' => $throwable->getMessage(),
            ]);

            return null;
        }
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
