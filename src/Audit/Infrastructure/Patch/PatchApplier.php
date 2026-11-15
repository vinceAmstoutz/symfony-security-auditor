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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch;

/**
 * Applies a file's hunks to its content, or tells it does not apply cleanly.
 * Each hunk must find the exact lines it expects: where it says they are,
 * shifted by what the hunks before it added or removed, or else at the one
 * place in the file that holds them. Lines found nowhere, or in more than one
 * place, leave the file as it is: a fix applied to code it was not written
 * for could open another hole. The file keeps its line endings.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PatchApplier
{
    public function apply(string $content, FilePatch $filePatch): ?string
    {
        $lineEnding = str_contains($content, "\r\n") ? "\r\n" : "\n";
        $endsWithNewline = str_ends_with($content, "\n");
        $lines = $this->linesOf($endsWithNewline ? substr($content, 0, -\strlen($lineEnding)) : $content, $lineEnding);

        $offset = 0;
        foreach ($filePatch->hunks as $diffHunk) {
            $position = $this->positionOf($lines, $diffHunk, $diffHunk->oldStart - 1 + $offset);
            if (null === $position) {
                return null;
            }

            array_splice($lines, $position, \count($diffHunk->oldLines), $diffHunk->newLines);
            $offset += \count($diffHunk->newLines) - \count($diffHunk->oldLines);
        }

        return implode($lineEnding, $lines).($endsWithNewline ? $lineEnding : '');
    }

    /**
     * @param non-empty-string $lineEnding
     *
     * @return list<string>
     */
    private function linesOf(string $content, string $lineEnding): array
    {
        return '' === $content ? [] : explode($lineEnding, $content);
    }

    /**
     * @param list<string> $lines
     */
    private function positionOf(array $lines, DiffHunk $diffHunk, int $statedPosition): ?int
    {
        if ($this->holdsAt($lines, $diffHunk->oldLines, $statedPosition)) {
            return $statedPosition;
        }

        if ([] === $diffHunk->oldLines) {
            return null;
        }

        $positions = array_values(array_filter(
            array_keys($lines),
            fn (int $position): bool => $this->holdsAt($lines, $diffHunk->oldLines, $position),
        ));

        return 1 === \count($positions) ? $positions[0] : null;
    }

    /**
     * @param list<string> $lines
     * @param list<string> $expected
     */
    private function holdsAt(array $lines, array $expected, int $position): bool
    {
        return $position >= 0 && $position <= \count($lines) && \array_slice($lines, $position, \count($expected)) === $expected;
    }
}
