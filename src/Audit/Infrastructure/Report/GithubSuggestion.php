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
    public const string MARKER_PREFIX = '<!-- symfony-security-auditor:suggestion:';

    private const int MINIMUM_FENCE_LENGTH = 3;

    private function __construct(
        private Vulnerability $vulnerability,
        private DiffHunk $diffHunk,
    ) {}

    public static function of(Vulnerability $vulnerability): ?self
    {
        $diffHunk = self::singleHunkOf($vulnerability);

        return $diffHunk instanceof DiffHunk ? new self($vulnerability, $diffHunk) : null;
    }

    public function commentSection(): string
    {
        return \sprintf(
            "%s, %s:\n\n%s",
            MarkdownTextEscaper::inlineCode($this->vulnerability->filePath()),
            $this->diffHunk->oldStart === $this->diffHunk->oldEnd() ? \sprintf('line %d', $this->diffHunk->oldStart) : \sprintf('lines %d to %d', $this->diffHunk->oldStart, $this->diffHunk->oldEnd()),
            $this->block(),
        );
    }

    /**
     * The review comment GitHub turns into a one-click fix on the lines it
     * replaces, with the lines it expects there so a workflow can check the
     * commit it comments on still holds them, and a key naming the finding and
     * those lines so a rerun does not post it twice.
     *
     * @return array{key: string, path: string, start_line: int, line: int, expected: list<string>, body: string}
     */
    public function reviewComment(ReportPathPrefix $reportPathPrefix): array
    {
        $key = \sprintf('%s:%d-%d', $this->vulnerability->fingerprint(), $this->diffHunk->oldStart, $this->diffHunk->oldEnd());

        return [
            'key' => $key,
            'path' => $reportPathPrefix->apply($this->vulnerability->filePath()),
            'start_line' => $this->diffHunk->oldStart,
            'line' => $this->diffHunk->oldEnd(),
            'expected' => $this->diffHunk->oldLines,
            'body' => \sprintf("**%s**\n\n%s\n\n%s%s -->", MarkdownTextEscaper::tableCell($this->vulnerability->title()), $this->block(), self::MARKER_PREFIX, $key),
        ];
    }

    private function block(): string
    {
        $code = implode("\n", array_map(
            static fn (string $line): string => TerminalTextSanitizer::stripControlCharacters(mb_scrub($line, 'UTF-8')),
            $this->diffHunk->newLines,
        ));
        $fence = $this->fenceAround($code);

        return \sprintf("%ssuggestion\n%s\n%s", $fence, $code, $fence);
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

    private function fenceAround(string $code): string
    {
        $fence = str_repeat('`', self::MINIMUM_FENCE_LENGTH);
        while (str_contains($code, $fence)) {
            $fence .= '`';
        }

        return $fence;
    }
}
