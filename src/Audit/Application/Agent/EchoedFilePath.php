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

use function Symfony\Component\String\u;

/**
 * `Vulnerability::filePath()` is free text echoed back by the LLM — the
 * `record_vulnerability` schema only constrains it to a non-blank string, with
 * no cross-check against the chunk's real file list — so a model quirk like a
 * leading `./` must not keep a finding from matching its `ProjectFile`.
 * `resolve()` names a finding by the known file its path denotes — an absolute
 * path, a leading slash, backslashes or a leading `./` alike — so one file has
 * one spelling in every id, fingerprint and code lookup.
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
     * @param list<ProjectFile> $knownFiles
     */
    public static function resolve(string $path, array $knownFiles): string
    {
        $echoed = self::comparable($path);
        foreach ($knownFiles as $knownFile) {
            if (self::comparable($knownFile->relativePath()) === $echoed || self::comparable($knownFile->absolutePath()) === $echoed) {
                return $knownFile->relativePath();
            }
        }

        return $path;
    }

    private static function comparable(string $path): string
    {
        return u(mb_scrub($path, 'UTF-8'))->replace('\\', '/')->replaceMatches('#^(?:\./|/)+#', '')->toString();
    }
}
