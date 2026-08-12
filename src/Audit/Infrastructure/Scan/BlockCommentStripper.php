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
    public function __construct(
        private StringLiteralMasker $stringLiteralMasker = new StringLiteralMasker(),
    ) {}

    /**
     * @return array{line: string, inside_block_comment: bool}
     */
    public function strip(string $line, bool $insideBlockComment): array
    {
        $kept = '';
        $remaining = $line;

        while (true) {
            if ($insideBlockComment) {
                $closeOffset = strpos($remaining, '*/');
                if (false === $closeOffset) {
                    return ['line' => $kept, 'inside_block_comment' => true];
                }

                $remaining = substr($remaining, $closeOffset + 2);
                $insideBlockComment = false;

                continue;
            }

            $openOffset = strpos($this->stringLiteralMasker->mask($remaining), '/*');
            if (false === $openOffset) {
                return ['line' => $kept.$remaining, 'inside_block_comment' => false];
            }

            $kept .= substr($remaining, 0, $openOffset);
            $remaining = substr($remaining, $openOffset + 2);
            $insideBlockComment = true;
        }
    }
}
