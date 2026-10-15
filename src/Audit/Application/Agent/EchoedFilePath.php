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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

use function Symfony\Component\String\b;

/**
 * `Vulnerability::filePath()` is free text echoed back by the LLM — the
 * `record_vulnerability` schema only constrains it to a non-blank string, with
 * no cross-check against the chunk's real file list — so a model quirk like a
 * leading `./` must not keep a finding from matching its `ProjectFile`.
 * `resolve()` names a finding by the known file its path denotes — an absolute
 * path, a leading slash, backslashes or a leading `./` alike — so one file has
 * one spelling in every id, fingerprint and code lookup. Paths are compared
 * byte for byte: one that names a known file as written keeps naming it, and a
 * folded spelling resolves only when it denotes one known file alone, so a
 * look-alike name (a backslash, another Unicode form) never takes the findings
 * of the file it resembles.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EchoedFilePath
{
    public static function normalize(string $path): string
    {
        return str_starts_with($path, './') ? substr($path, 2) : $path;
    }

    /**
     * Whether `$path` names the file with these paths, compared as
     * {@see self::resolve()} compares them.
     */
    public static function denotes(string $path, string $relativePath, string $absolutePath): bool
    {
        $echoed = self::comparable($path);

        return self::comparable($relativePath) === $echoed || self::comparable($absolutePath) === $echoed;
    }

    /**
     * Whether `$path` names the file `$relativePath` of the project at
     * `$projectPath`, by its relative or its absolute path.
     */
    public static function denotesProjectFile(string $path, string $relativePath, string $projectPath): bool
    {
        return self::denotes($path, $relativePath, \sprintf('%s/%s', $projectPath, $relativePath));
    }

    /**
     * @param list<ProjectFile> $knownFiles
     */
    public static function resolve(string $path, array $knownFiles): string
    {
        foreach ($knownFiles as $knownFile) {
            if ($knownFile->relativePath() === $path || $knownFile->absolutePath() === $path) {
                return $knownFile->relativePath();
            }
        }

        $denoted = self::denotedBy(self::comparable($path), $knownFiles);

        return 1 === \count($denoted) ? $denoted[0] : $path;
    }

    /**
     * @param list<ProjectFile> $knownFiles
     *
     * @return list<string>
     */
    private static function denotedBy(string $echoed, array $knownFiles): array
    {
        $denoted = [];
        foreach ($knownFiles as $knownFile) {
            if (self::comparable($knownFile->relativePath()) === $echoed || self::comparable($knownFile->absolutePath()) === $echoed) {
                $denoted[] = $knownFile->relativePath();
            }
        }

        return $denoted;
    }

    private static function comparable(string $path): string
    {
        return b($path)->replace('\\', '/')->replaceMatches('#^(?:\./|/)+#', '')->toString();
    }
}
