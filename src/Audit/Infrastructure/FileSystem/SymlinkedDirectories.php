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

use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFileReason;

/**
 * The directories a walk does not enter because they are symbolic links: the
 * scan never follows one, so each is reported as left out, under the same
 * rules as the walk for dot directories and `.gitignore` files.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymlinkedDirectories
{
    public function __construct(private LoggerInterface $logger) {}

    /**
     * @param list<string> $directories the directories the walk starts from
     *
     * @return list<SkippedFile>
     */
    public function in(array $directories, string $projectPath, bool $includeDotfiles, bool $respectGitignore): array
    {
        $finder = (new Finder())
            ->directories()
            ->ignoreDotFiles(!$includeDotfiles)
            ->ignoreUnreadableDirs()
            ->in($directories)
            ->filter(static fn (SplFileInfo $splFileInfo): bool => $splFileInfo->isLink());

        $skippedFiles = [];
        foreach ((new GitignoreRespectingWalk($respectGitignore, $this->logger))->files($finder, $projectPath) as $symlinkedDirectory) {
            $this->logger->warning('Skipped symlinked directory', ['path' => $symlinkedDirectory->getPathname()]);
            $skippedFiles[] = new SkippedFile(Utf8Normalizer::normalize(Path::makeRelative($symlinkedDirectory->getPathname(), $projectPath)), SkippedFileReason::Symlink);
        }

        return $skippedFiles;
    }
}
