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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\KnownFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Turns the gaps the coverage critic recorded or answered into
 * {@see CoverageGap}s on the audited files, leaving out a gap that names no
 * file, a file the run did not audit, or no hypothesis or attack class, and
 * keeps the first ones up to the most the critic may name.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CoverageGapFactory
{
    /**
     * @param list<mixed>       $payloads
     * @param list<ProjectFile> $files
     *
     * @return list<CoverageGap>
     */
    public static function fromPayloads(array $payloads, array $files, int $maxGaps): array
    {
        $filesByPath = [];
        foreach ($files as $file) {
            $filesByPath[$file->relativePath()] = $file;
        }

        $knownFiles = new KnownFiles($files);
        $gaps = [];
        foreach ($payloads as $payload) {
            $gap = \is_array($payload) ? self::gapFrom($payload, $filesByPath, $knownFiles) : null;
            if ($gap instanceof CoverageGap) {
                $gaps[] = $gap;
            }
        }

        return \array_slice($gaps, 0, $maxGaps);
    }

    /**
     * @param array<array-key, mixed>    $payload
     * @param array<string, ProjectFile> $filesByPath
     */
    private static function gapFrom(array $payload, array $filesByPath, KnownFiles $knownFiles): ?CoverageGap
    {
        $gapFiles = self::filesNamedBy($payload['files'] ?? null, $filesByPath, $knownFiles);
        $hypothesis = self::text($payload['hypothesis'] ?? null);
        $attackClass = self::text($payload['attack_class'] ?? null);

        if ([] === $gapFiles || null === $hypothesis || null === $attackClass) {
            return null;
        }

        return new CoverageGap($gapFiles, $hypothesis, $attackClass);
    }

    /**
     * @param array<string, ProjectFile> $filesByPath
     *
     * @return list<ProjectFile> none when the value names no file or a file the run did not audit
     */
    private static function filesNamedBy(mixed $paths, array $filesByPath, KnownFiles $knownFiles): array
    {
        if (!\is_array($paths)) {
            return [];
        }

        $gapFiles = [];
        foreach ($paths as $path) {
            if (!\is_string($path)) {
                return [];
            }

            $relativePath = $knownFiles->name($path);
            if (!\array_key_exists($relativePath, $filesByPath)) {
                return [];
            }

            $gapFiles[] = $filesByPath[$relativePath];
        }

        return $gapFiles;
    }

    private static function text(mixed $value): ?string
    {
        return \is_string($value) && '' !== trim($value) ? $value : null;
    }
}
