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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\DiffHunk;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\UnifiedDiff;

/**
 * A suggested fix written as a GitHub `suggestion` block: the lines it puts
 * in place of the lines it names. GitHub can express only one run of
 * replaced lines, so a fix that touches several hunks or files, or only adds
 * lines, gets none. The fence is one backtick longer than any run of
 * backticks the code holds, so the code cannot close it early.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GithubSuggestion
{
    private const int MINIMUM_FENCE_LENGTH = 3;

    public static function for(Vulnerability $vulnerability): ?string
    {
        $diffHunk = self::singleHunkOf($vulnerability);
        if (!$diffHunk instanceof DiffHunk) {
            return null;
        }

        $code = implode("\n", array_map(
            static fn (string $line): string => TerminalTextSanitizer::stripControlCharacters(mb_scrub($line, 'UTF-8')),
            $diffHunk->newLines,
        ));
        $fence = self::fenceAround($code);

        return \sprintf(
            "%s, %s:\n\n%ssuggestion\n%s\n%s",
            MarkdownTextEscaper::inlineCode($vulnerability->filePath()),
            $diffHunk->oldStart === $diffHunk->oldEnd() ? \sprintf('line %d', $diffHunk->oldStart) : \sprintf('lines %d to %d', $diffHunk->oldStart, $diffHunk->oldEnd()),
            $fence,
            $code,
            $fence,
        );
    }

    private static function singleHunkOf(Vulnerability $vulnerability): ?DiffHunk
    {
        $unifiedDiff = UnifiedDiff::parse($vulnerability->suggestedFix() ?? '');
        $filePatches = $unifiedDiff instanceof UnifiedDiff ? $unifiedDiff->filePatches : [];
        if (1 !== \count($filePatches) || $filePatches[0]->path !== $vulnerability->filePath() || 1 !== \count($filePatches[0]->hunks)) {
            return null;
        }

        $diffHunk = $filePatches[0]->hunks[0];

        return [] === $diffHunk->oldLines ? null : $diffHunk;
    }

    private static function fenceAround(string $code): string
    {
        $fence = str_repeat('`', self::MINIMUM_FENCE_LENGTH);
        while (str_contains($code, $fence)) {
            $fence .= '`';
        }

        return $fence;
    }
}
