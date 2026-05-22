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

final readonly class ProjectFileScanner implements ProjectFileScannerInterface
{
    /** @var list<string> */
    private const array PHP_EXTENSIONS = ['php'];

    /** @var list<string> */
    private const array TEMPLATE_EXTENSIONS = ['twig'];

    /** @var list<string> */
    private const array CONFIG_EXTENSIONS = ['yaml', 'yml', 'xml'];

    /** @var list<string> */
    private const array HARD_EXCLUDED_DIRS = [
        'vendor',
        'node_modules',
        '.git',
        'var/cache',
        'var/log',
        'public/bundles',
    ];

    public const int DEFAULT_MAX_FILE_SIZE_KB = 512;

    /**
     * @param list<string>                  $additionalExcludedDirs appended to the hard defaults; never replaces them
     * @param ?Closure(SplFileInfo): string $fileReader             defaults to SplFileInfo::getContents; tests inject a stub
     */
    public function __construct(
        private LoggerInterface $logger,
        private array $additionalExcludedDirs = [],
        private bool $respectGitignore = false,
        private int $maxFileSizeKb = self::DEFAULT_MAX_FILE_SIZE_KB,
        private ?Closure $fileReader = null,
    ) {}

    /**
     * @return list<ProjectFile>
     */
    public function scan(string $projectPath): array
    {
        $this->logger->info('Scanning project', ['path' => $projectPath]);

        $extensions = array_merge(
            array_map(static fn (string $ext): string => '*.'.$ext, self::PHP_EXTENSIONS),
            array_map(static fn (string $ext): string => '*.'.$ext, self::TEMPLATE_EXTENSIONS),
            array_map(static fn (string $ext): string => '*.'.$ext, self::CONFIG_EXTENSIONS),
        );

        $finder = (new Finder())
            ->files()
            ->in($projectPath)
            ->name($extensions)
            ->exclude(array_merge(self::HARD_EXCLUDED_DIRS, $this->additionalExcludedDirs))
            ->size(\sprintf('<= %dK', $this->maxFileSizeKb));

        if ($this->respectGitignore) {
            $finder->ignoreVCSIgnored(true);
        }

        $reader = $this->fileReader ?? static fn (SplFileInfo $splFile): string => $splFile->getContents();
        $files = [];

        /** @var SplFileInfo $splFile */
        foreach ($finder as $splFile) {
            try {
                $files[] = ProjectFile::create(
                    relativePath: Path::makeRelative($splFile->getPathname(), $projectPath),
                    absolutePath: $splFile->getPathname(),
                    content: $reader($splFile),
                );
            } catch (Throwable $exception) {
                $this->logger->warning('Failed to read file', [
                    'path' => $splFile->getPathname(),
                    'error' => $exception->getMessage(),
                ]);
            }
        }

        $this->logger->info('Scan complete', ['files' => \count($files)]);

        return $files;
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
