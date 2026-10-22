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
use Symfony\Component\Finder\Gitignore;
use Symfony\Component\Finder\SplFileInfo;
use Symfony\Component\String\AbstractString;

use function Symfony\Component\String\b;

/**
 * The `.gitignore` rules of a project, read the way Finder's
 * `ignoreVCSIgnored()` reads them: the `.gitignore` files from the root of the
 * git repository holding the project, or of the project itself, down to the
 * file; the last matching rule of the deepest one decides, and a file inside
 * an ignored directory is ignored with it. A `.gitignore` that is not a file,
 * such as a directory a repository commits under that name, holds no rule.
 *
 * Mutable by design: it keeps the rules it read across the files of a walk,
 * so it opts out of the final readonly rule as a stateful collaborator (see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ReadableGitignores
{
    /** @var array<string, array<array{0: string, 1: bool, 2: bool}>> each directory's rules as regex, negated and directory-only, the last rule first */
    private array $rules = [];

    private function __construct(
        private readonly string $baseDirectory,
        private readonly LoggerInterface $logger,
    ) {}

    public static function of(string $projectPath, LoggerInterface $logger): self
    {
        $realProjectPath = self::normalized((new Filesystem())->readlink($projectPath, true) ?? $projectPath);
        foreach ([$realProjectPath, ...self::ancestorsOf($realProjectPath)] as $directory) {
            if (file_exists(\sprintf('%s/.git', $directory))) {
                return new self($directory, $logger);
            }
        }

        return new self($realProjectPath, $logger);
    }

    public function ignore(SplFileInfo $splFile): bool
    {
        return $this->isIgnored(self::normalized((new Filesystem())->readlink($splFile->getPathname(), true) ?? $splFile->getPathname()));
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

    private function isIgnored(string $path): bool
    {
        $directories = array_filter(self::ancestorsOf($path), fn (string $directory): bool => str_starts_with($directory, $this->baseDirectory));
        $parent = $directories[0] ?? null;
        if (null !== $parent && $this->isIgnored($parent)) {
            return true;
        }

        return $this->deepestRuleIgnores($path, $directories);
    }

    /**
     * @param array<int, string> $directories the directories holding the path, the deepest first
     */
    private function deepestRuleIgnores(string $path, array $directories): bool
    {
        $isDirectory = is_dir($path);
        foreach ($directories as $directory) {
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
