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

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Strips block-comment content from a line, carrying the open/close state
 * across lines regardless of whether either line is elided.
 */
final readonly class BlockCommentStripper
{
    /**
     * @return array{line: string, inside_block_comment: bool}
     */
    public function strip(string $line, bool $insideBlockComment): array
    {
        return $insideBlockComment || str_contains($line, '/*')
            ? $this->scan($line, $insideBlockComment)
            : ['line' => $line, 'inside_block_comment' => false];
    }

    /**
     * @return array{line: string, inside_block_comment: bool}
     */
    private function scan(string $line, bool $insideBlockComment): array
    {
        $closingLimits = LiteralScanState::closingLimits($line);
        $state = CommentScanState::start($line, $insideBlockComment);
        $kept = '';

        foreach (str_split($line) as $offset => $char) {
            $state = $state->advance($line, $offset, $char, $closingLimits);

            if (!$state->swallows($offset)) {
                $kept .= $char;
            }
        }

        return ['line' => $kept, 'inside_block_comment' => $state->endsInsideComment()];
    }
}
