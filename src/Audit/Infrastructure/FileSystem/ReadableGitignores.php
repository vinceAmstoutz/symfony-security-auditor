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
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\Gitignore;
use Symfony\Component\Finder\SplFileInfo;
use Symfony\Component\String\AbstractString;

use function Symfony\Component\String\b;

/**
 * The `.gitignore` rules of a walked directory, read the way Finder's
 * `ignoreVCSIgnored()` reads them: the `.gitignore` files from the root of the
 * git repository holding the directory, or of the directory itself, down to
 * the file; the last matching rule of the deepest one decides, and a file inside
 * an ignored directory is ignored with it. A `.gitignore` that is not a file,
 * such as a directory a repository commits under that name, holds no rule.
 * Each path is decided once, from the verdict the walk carries down from the
 * directory holding it, since the walk enters a directory before what it
 * holds; only the walked directory, which the walk never gives, and a
 * symbolic link, read at its target as Finder reads it, are decided from the
 * directories holding them.
 *
 * Mutable by design: it keeps the rules it read and the verdicts it reached
 * across the files of a walk, so it opts out of the final readonly rule as a
 * stateful collaborator (see .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ReadableGitignores
{
    /** @var array<string, array<array{0: string, 1: bool, 2: bool}>> each directory's rules as regex, negated and directory-only, the last rule first */
    private array $rules = [];

    /** @var array<string, bool> whether each path the walk reached, other than a symbolic link, is ignored, by its real path */
    private array $verdicts = [];

    private function __construct(
        private readonly string $baseDirectory,
        private readonly LoggerInterface $logger,
    ) {}

    public static function of(string $walkedDirectory, LoggerInterface $logger): self
    {
        $realWalkedDirectory = self::normalized((new Filesystem())->readlink($walkedDirectory, true) ?? $walkedDirectory);
        foreach ([$realWalkedDirectory, ...self::ancestorsOf($realWalkedDirectory)] as $directory) {
            if (file_exists(\sprintf('%s/.git', $directory))) {
                return new self($directory, $logger);
            }
        }

        return new self($realWalkedDirectory, $logger);
    }

    /**
     * Finder calls a prune filter on each directory before it enters it, and
     * every filter on each path it yields: the first records the verdict of
     * every path it is given and enters every directory, as Finder's own
     * reading does, so the second only reads it back.
     */
    public function applyTo(Finder $finder): Finder
    {
        return $finder
            ->filter($this->recordVerdict(...), true)
            ->filter(fn (SplFileInfo $splFile): bool => !$this->ignores($splFile));
    }

    private function recordVerdict(SplFileInfo $splFile): bool
    {
        if (!$splFile->isLink()) {
            $path = $this->realPathOf($splFile);
            $this->verdicts[$path] = $this->holdingDirectoryIgnores($splFile, $path) || $this->deepestRuleIgnores($path);
        }

        return true;
    }

    /**
     * The directory holding a path at the top of the walk is the walked
     * directory itself, which the walk never gives.
     */
    private function holdingDirectoryIgnores(SplFileInfo $splFile, string $path): bool
    {
        return '' === $splFile->getRelativePath() ? $this->isIgnored(\dirname($path)) : $this->verdicts[\dirname($path)];
    }

    private function ignores(SplFileInfo $splFile): bool
    {
        $path = $this->realPathOf($splFile);

        return $splFile->isLink() ? $this->isIgnored($path) : $this->verdicts[$path];
    }

    private function realPathOf(SplFileInfo $splFile): string
    {
        return self::normalized((new Filesystem())->readlink($splFile->getPathname(), true) ?? $splFile->getPathname());
    }

    /**
     * @return list<string> the parent directory first, the root last
     */
    private static function ancestorsOf(string $path): array
    {
        $ancestors = [];
        for ($directory = \dirname($path); $directory !== $path; $directory = \dirname($path = $directory)) {
            $ancestors[] = $directory;
        }

        return $ancestors;
    }

    private static function normalized(string $path): string
    {
        return strtr($path, \DIRECTORY_SEPARATOR, '/');
    }

    /**
     * A path is ignored when the rules ignore it or a directory holding it
     * below the base, read from the base down: below an ignored directory,
     * no rule is read.
     */
    private function isIgnored(string $path): bool
    {
        foreach ([...array_reverse($this->directoriesHolding($path)), $path] as $candidate) {
            if ($this->deepestRuleIgnores($candidate)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, string> the directories holding the path from the base down, the deepest first
     */
    private function directoriesHolding(string $path): array
    {
        return array_filter(self::ancestorsOf($path), fn (string $directory): bool => str_starts_with($directory, $this->baseDirectory));
    }

    private function deepestRuleIgnores(string $path): bool
    {
        $isDirectory = is_dir($path);
        foreach ($this->directoriesHolding($path) as $directory) {
            $verdict = $this->lastMatchingRuleIgnores($directory, substr($path, \strlen($directory) + 1), $isDirectory);
            if (null !== $verdict) {
                return $verdict;
            }
        }

        return false;
    }

    private function lastMatchingRuleIgnores(string $directory, string $relativePath, bool $isDirectory): ?bool
    {
        foreach ($this->rules[$directory] ??= $this->rulesOf(\sprintf('%s/.gitignore', $directory)) as [$regex, $isNegated, $isDirectoryOnly]) {
            if ((!$isDirectoryOnly || $isDirectory) && 1 === preg_match($regex, $relativePath, $matches) && $matches[0] === $relativePath) {
                return !$isNegated;
            }
        }

        return null;
    }

    /**
     * @return array<array{0: string, 1: bool, 2: bool}>
     */
    private function rulesOf(string $gitignore): array
    {
        if (!file_exists($gitignore)) {
            return [];
        }

        if (!is_file($gitignore)) {
            $this->logger->warning('Read no rule from a .gitignore that is not a file', ['path' => $gitignore]);

            return [];
        }

        return array_reverse(array_map(fn (AbstractString $string): array => $this->ruleOf($string->toString()), b((new Filesystem())->readFile($gitignore))->split('~\r\n?|\n~', null, \PREG_SPLIT_NO_EMPTY)));
    }

    /**
     * A line opening with `#` is a comment, so a pattern that opens with one
     * once its `!` is set aside is escaped.
     *
     * @return array{0: string, 1: bool, 2: bool}
     */
    private function ruleOf(string $line): array
    {
        $pattern = str_starts_with($line, '#') ? '' : (preg_replace('~(?<!\\\\) +$~', '', $line) ?? $line);
        $isNegated = str_starts_with($pattern, '!');
        $pattern = $isNegated ? substr($pattern, 1) : $pattern;
        $isDirectoryOnly = str_ends_with($pattern, '/');
        $pattern = $isDirectoryOnly ? substr($pattern, 0, -1) : $pattern;

        return [Gitignore::toRegex(str_starts_with($pattern, '#') ? \sprintf('\\%s', $pattern) : $pattern), $isNegated, $isDirectoryOnly];
    }
}
