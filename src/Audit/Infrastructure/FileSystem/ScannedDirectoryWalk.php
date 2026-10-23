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

use FilesystemIterator;
use Psr\Log\LoggerInterface;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\Glob;
use Symfony\Component\Finder\SplFileInfo;
use UnexpectedValueException;

/**
 * The one walk the scan makes of a directory it scans: it gives the files with
 * a scanned name and each symbolic link to a directory, which the scan never
 * enters and reports as left out, so no second walk looks for those links. A
 * link that leads nowhere is given neither way, as Finder's own `files()` and
 * `directories()` leave it out, and a directory the process cannot list is
 * not entered.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ScannedDirectoryWalk
{
    /** @var list<string> */
    private const array PHP_EXTENSIONS = ['php'];

    /** @var list<string> */
    private const array TEMPLATE_EXTENSIONS = ['twig'];

    /** @var list<string> */
    private const array CONFIG_EXTENSIONS = ['yaml', 'yml', 'xml'];

    /** @var list<string> */
    private array $nameRegexes;

    public function __construct(private LoggerInterface $logger)
    {
        $this->nameRegexes = array_map(Glob::toRegex(...), $this->namePatterns());
    }

    public function in(string $directory, bool $includeDotfiles): Finder
    {
        return (new Finder())
            ->ignoreDotFiles(!$includeDotfiles)
            ->in($directory)
            ->filter($this->gives(...))
            ->filter($this->entersReadableDirectory(...), true);
    }

    /**
     * A glob's `*` never matches a leading dot, so each extension is matched
     * as `.*.ext` too: the dot files a walk reads when it is asked to.
     *
     * @return list<string>
     */
    private function namePatterns(): array
    {
        $extensions = [...self::PHP_EXTENSIONS, ...self::TEMPLATE_EXTENSIONS, ...self::CONFIG_EXTENSIONS];

        return [
            ...array_map(static fn (string $extension): string => \sprintf('*.%s', $extension), $extensions),
            ...array_map(static fn (string $extension): string => \sprintf('.*.%s', $extension), $extensions),
        ];
    }

    private function gives(SplFileInfo $splFile): bool
    {
        if ($splFile->isDir()) {
            return $splFile->isLink();
        }

        return ($splFile->isFile() || !$splFile->isLink()) && $this->hasAScannedName($splFile->getFilename());
    }

    private function hasAScannedName(string $filename): bool
    {
        foreach ($this->nameRegexes as $nameRegex) {
            if (1 === preg_match($nameRegex, $filename)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Finder asks a prune filter about each directory before it enters it, and
     * about each entry it gives: a symbolic link to a directory is given, not
     * entered.
     */
    private function entersReadableDirectory(SplFileInfo $splFile): bool
    {
        if (!$splFile->isDir() || $splFile->isLink()) {
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
}
