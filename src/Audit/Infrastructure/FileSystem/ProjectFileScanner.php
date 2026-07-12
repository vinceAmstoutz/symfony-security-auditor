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
use Override;
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

        $files = array_merge(
            $this->scanDirectories($directories, $projectPath, $reader),
            $this->scanExplicitFiles($explicitFiles, $projectPath, $reader),
        );

        $this->logger->info('Scan complete', ['files' => \count($files)]);

        return $files;
    }

    /**
     * @param list<string>                 $directories
     * @param Closure(SplFileInfo): string $reader
     *
     * @return list<ProjectFile>
     */
    private function scanDirectories(array $directories, string $projectPath, Closure $reader): array
    {
        if ([] === $directories) {
            return [];
        }

        $finder = (new Finder())
            ->files()
            ->in($directories)
            ->name($this->finderNamePatterns())
            ->size(\sprintf('<= %dKi', $this->maxFileSizeKb));

        return $this->collectFilesFrom($finder, $projectPath, $reader);
    }

    /**
     * @param list<string>                 $explicitFiles
     * @param Closure(SplFileInfo): string $reader
     *
     * @return list<ProjectFile>
     */
    private function scanExplicitFiles(array $explicitFiles, string $projectPath, Closure $reader): array
    {
        $files = [];
        foreach ($explicitFiles as $explicitFile) {
            $explicitFinder = (new Finder())
                ->files()
                ->ignoreDotFiles(false)
                ->in(\dirname($explicitFile))
                ->depth('== 0')
                ->name(basename($explicitFile))
                ->size(\sprintf('<= %dKi', $this->maxFileSizeKb));

            $files = array_merge($files, $this->collectFilesFrom($explicitFinder, $projectPath, $reader));
        }

        return $files;
    }

    /**
     * @param Closure(SplFileInfo): string $reader
     *
     * @return list<ProjectFile>
     */
    private function collectFilesFrom(Finder $finder, string $projectPath, Closure $reader): array
    {
        if ($this->respectGitignore) {
            $finder->ignoreVCSIgnored(true);
        }

        $files = [];
        /** @var SplFileInfo $splFile */
        foreach ($finder as $splFile) {
            $file = $this->buildProjectFile($splFile, $projectPath, $reader);
            if ($file instanceof ProjectFile) {
                $files[] = $file;
            }
        }

        return $files;
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
     * @return array{0: list<string>, 1: list<string>}
     */
    private function resolveIncludedPaths(string $projectPath): array
    {
        $directories = [];
        $explicitFiles = [];
        foreach ($this->includedPaths as $includedPath) {
            $resolved = $projectPath.\DIRECTORY_SEPARATOR.$includedPath;
            if (is_link($resolved)) {
                $this->logger->warning('Skipped symlinked included path', ['path' => $resolved]);

                continue;
            }

            if (is_dir($resolved)) {
                $directories[] = $resolved;

                continue;
            }

            if (is_file($resolved)) {
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
        if ($splFile->isLink()) {
            $this->logger->warning('Skipped symlinked file', ['path' => $splFile->getPathname()]);

            return null;
        }

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
