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

use function Symfony\Component\String\u;

/**
 * A unified-diff patch read from a model's answer, ignoring the prose and code
 * fences around it and replacing invalid UTF-8. parse() returns null for a
 * patch that creates, deletes or renames a file, leaves the project, has a
 * header with no hunk, a hunk whose counts do not add up or a hunk line past
 * the lines its header counts, so no part of it is applied.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class UnifiedDiff
{
    private const string NEW_FILE_PREFIX = '+++ ';

    private const string NO_NEWLINE_MARKER = '\\';

    private const string HUNK_LINE = '/^(?:[-+ ]|@@)/';

    private const string HUNK_LINE_AFTER_A_BLANK_LINE = '/^(?: |@@)/';

    private const string HUNK_HEADER = '/^@@ -(\d+)(?:,(\d+))? \+\d+(?:,(\d+))? @@/';

    /**
     * @param non-empty-list<FilePatch> $filePatches
     */
    private function __construct(
        public array $filePatches,
    ) {}

    public static function parse(string $patch): ?self
    {
        $lines = explode("\n", u(mb_scrub($patch, 'UTF-8'))->replace("\r\n", "\n")->toString());

        $filePatches = [];
        $index = 0;
        while (null !== ($index = self::nextFileHeader($lines, $index))) {
            $filePatch = self::filePatch($lines, $index);
            if (null === $filePatch) {
                return null;
            }

            [$filePatches[], $index] = $filePatch;
        }

        return [] === $filePatches ? null : new self($filePatches);
    }

    /**
     * @param list<string> $lines
     */
    private static function nextFileHeader(array $lines, int $from): ?int
    {
        for ($index = $from, $count = \count($lines) - 1; $index < $count; ++$index) {
            if (self::isFileHeader($lines, $index)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * @param list<string> $lines
     */
    private static function isFileHeader(array $lines, int $index): bool
    {
        return str_starts_with($lines[$index], '--- ') && str_starts_with($lines[$index + 1] ?? '', self::NEW_FILE_PREFIX);
    }

    /**
     * @param list<string> $lines
     *
     * @return array{FilePatch, int}|null
     */
    private static function filePatch(array $lines, int $header): ?array
    {
        $path = self::pathOf($lines[$header], '--- ', 'a/') === self::pathOf($lines[$header + 1], self::NEW_FILE_PREFIX, 'b/')
            ? self::pathOf($lines[$header + 1], self::NEW_FILE_PREFIX, 'b/')
            : null;

        $hunks = [];
        $index = $header + 2;
        while (null !== $path && 1 === preg_match(self::HUNK_HEADER, $lines[$index] ?? '', $counts)) {
            $hunk = self::hunk($lines, $index + 1, $counts);
            if (null === $hunk) {
                return null;
            }

            [$hunks[], $index] = $hunk;
        }

        return null === $path || [] === $hunks || self::hunkLineFollows($lines, $index) ? null : [new FilePatch($path, $hunks), $index];
    }

    /**
     * @param list<string> $lines
     */
    private static function hunkLineFollows(array $lines, int $from): bool
    {
        $next = self::nextContentLine($lines, $from);
        if (null === $next) {
            return false;
        }

        $pattern = self::holdsABlankLine($lines, $from, $next) ? self::HUNK_LINE_AFTER_A_BLANK_LINE : self::HUNK_LINE;

        return 1 === preg_match($pattern, $lines[$next]) && !self::isFileHeader($lines, $next);
    }

    /**
     * @param list<string> $lines
     */
    private static function nextContentLine(array $lines, int $from): ?int
    {
        for ($index = $from, $count = \count($lines); $index < $count; ++$index) {
            if ('' !== $lines[$index] && !str_starts_with($lines[$index], self::NO_NEWLINE_MARKER)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * @param list<string> $lines
     */
    private static function holdsABlankLine(array $lines, int $from, int $to): bool
    {
        return \in_array('', \array_slice($lines, $from, $to - $from), true);
    }

    private static function pathOf(string $line, string $marker, string $side): ?string
    {
        $path = u($line)->trimPrefix($marker)->before("\t")->trimEnd();
        if (!$path->startsWith($side)) {
            return null;
        }

        $relativePath = $path->trimPrefix($side)->toString();

        return self::staysInTheProject($relativePath) ? $relativePath : null;
    }

    private static function staysInTheProject(string $relativePath): bool
    {
        $segments = u($relativePath)->replace('\\', '/')->split('/');

        return '' !== $segments[0]->toString()
            && !u($segments[0]->toString())->endsWith(':')
            && [] === array_filter($segments, static fn ($segment): bool => '..' === $segment->toString());
    }

    /**
     * @param list<string>              $lines
     * @param array<int|string, string> $counts
     *
     * @return array{DiffHunk, int}|null
     */
    private static function hunk(array $lines, int $from, array $counts): ?array
    {
        $oldCount = self::lineCount($counts[2] ?? '');
        $hunkBody = self::hunkBody($lines, $from, $oldCount, self::lineCount($counts[3] ?? ''));
        if (null === $hunkBody) {
            return null;
        }

        [$oldLines, $newLines, $index] = $hunkBody;
        $oldStart = (int) $counts[1] + (0 === $oldCount ? 1 : 0);

        return [new DiffHunk($oldStart, $oldLines, $newLines), $index];
    }

    private static function lineCount(string $count): int
    {
        return '' === $count ? 1 : (int) $count;
    }

    /**
     * @param list<string> $lines
     *
     * @return array{list<string>, list<string>, int}|null
     */
    private static function hunkBody(array $lines, int $index, int $oldCount, int $newCount): ?array
    {
        $oldLines = [];
        $newLines = [];
        while (\count($oldLines) < $oldCount || \count($newLines) < $newCount) {
            $marker = self::markerOf($lines[$index] ?? null);
            if (null === $marker) {
                return null;
            }

            [$removed, $added] = self::sidesOf($marker, substr($lines[$index], 1));
            array_push($oldLines, ...$removed);
            array_push($newLines, ...$added);
            ++$index;
        }

        return \count($oldLines) === $oldCount && \count($newLines) === $newCount ? [$oldLines, $newLines, $index] : null;
    }

    /**
     * @return array{list<string>, list<string>} the line as the file has it before the patch and after
     */
    private static function sidesOf(string $marker, string $text): array
    {
        return match ($marker) {
            '-' => [[$text], []],
            '+' => [[], [$text]],
            ' ' => [[$text], [$text]],
            default => [[], []],
        };
    }

    private static function markerOf(?string $line): ?string
    {
        $marker = null === $line ? null : ($line[0] ?? ' ');

        return \in_array($marker, ['-', '+', ' ', self::NO_NEWLINE_MARKER], true) ? $marker : null;
    }
}
