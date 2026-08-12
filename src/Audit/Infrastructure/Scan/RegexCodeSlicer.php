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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Replaces every line of a PHP file the collaborators below don't retain with
 * a `// elided` placeholder, preserving total line count:
 * {@see LineRetentionDeciderInterface} decides retention,
 * {@see ParenContinuationTracker} extends it across an open multi-line
 * signature, {@see HeredocLineTracker} retains a heredoc/nowdoc body
 * verbatim, and {@see BlockCommentStripper} feeds both trackers comment-free
 * text. Non-PHP files and files under `minLinesBeforeSlicing` pass through
 * unchanged.
 */
final readonly class RegexCodeSlicer implements CodeSlicerInterface
{
    public const int DEFAULT_MIN_LINES_BEFORE_SLICING = 80;

    private const string ELIDED_PLACEHOLDER = '// elided';

    public function __construct(
        private int $minLinesBeforeSlicing = self::DEFAULT_MIN_LINES_BEFORE_SLICING,
        private LineRetentionDeciderInterface $lineRetentionDecider = new ContinuationForcedLineRetentionDecider(new SecurityRelevantLineClassifier()),
        private BlockCommentStripper $blockCommentStripper = new BlockCommentStripper(),
        private ParenContinuationTracker $parenContinuationTracker = new ParenContinuationTracker(),
        private HeredocLineTracker $heredocLineTracker = new HeredocLineTracker(),
    ) {}

    #[Override]
    public function slice(ProjectFile $projectFile): string
    {
        if (!$this->shouldSlice($projectFile)) {
            return $projectFile->content();
        }

        $output = [];
        $openParenDepth = 0;
        $openStringDelimiter = null;
        $insideBlockComment = false;
        $openHeredocIdentifier = null;
        foreach (explode("\n", $projectFile->content()) as $line) {
            if (null !== $openHeredocIdentifier) {
                $output[] = $line;
                [$openHeredocIdentifier, $openParenDepth, $openStringDelimiter] = $this->heredocLineTracker->consumeLine($line, $openHeredocIdentifier, $openParenDepth, $openStringDelimiter);

                continue;
            }

            $blockCommentState = $this->blockCommentStripper->strip($line, $insideBlockComment);
            $insideBlockComment = $blockCommentState['inside_block_comment'];

            $heredocIdentifier = $this->heredocLineTracker->identifierOpenedBy($blockCommentState['line']);
            $retain = $this->lineRetentionDecider->isRetained($line, new LineRetentionContext($openParenDepth, null !== $heredocIdentifier));
            $output[] = $retain ? $line : self::ELIDED_PLACEHOLDER;

            if (null !== $heredocIdentifier) {
                $openHeredocIdentifier = $heredocIdentifier;

                continue;
            }

            [$openParenDepth, $openStringDelimiter] = $this->parenContinuationTracker->advance($retain, $blockCommentState['line'], $openParenDepth, $openStringDelimiter);
        }

        return implode("\n", $output);
    }

    private function shouldSlice(ProjectFile $projectFile): bool
    {
        if ('php' !== pathinfo($projectFile->relativePath(), \PATHINFO_EXTENSION)) {
            return false;
        }

        return $projectFile->linesCount() >= $this->minLinesBeforeSlicing;
    }
}
