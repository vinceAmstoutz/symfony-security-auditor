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
 * A suggested fix as a GitHub `suggestion` block, which replaces one run of
 * lines: a fix that touches several hunks or files, or only adds lines, gets
 * none. Its fence outlasts any backtick run in the code.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
     * Returns the review comment GitHub turns into a one-click fix, with the
     * lines it expects to replace and a key that keeps a rerun from posting
     * it twice.
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
        preg_match_all('/`+/', $code, $backtickRuns);
        $longestRun = max([self::MINIMUM_FENCE_LENGTH - 1, ...array_map(\strlen(...), $backtickRuns[0])]);

        return str_repeat('`', $longestRun + 1);
    }
}
