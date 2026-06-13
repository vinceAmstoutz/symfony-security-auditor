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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Renders the `<file>` source blocks of the attacker user message, each line
 * prefixed with its 1-based number (`NNN | code`) so the model can populate
 * `line_start` / `line_end` without counting.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NumberedFileContextRenderer
{
    /** @param list<ProjectFile> $files */
    public static function render(array $files): string
    {
        $parts = [];
        foreach ($files as $file) {
            $parts[] = \sprintf(
                "<file path=\"%s\" type=\"%s\">\n%s\n</file>",
                $file->relativePath(),
                $file->type(),
                self::numberLines($file->content()),
            );
        }

        return implode("\n\n", $parts);
    }

    private static function numberLines(string $content): string
    {
        $lines = explode("\n", $content);
        $numbered = [];
        foreach ($lines as $index => $line) {
            $numbered[] = \sprintf('%3d | %s', $index + 1, $line);
        }

        return implode("\n", $numbered);
    }
}
