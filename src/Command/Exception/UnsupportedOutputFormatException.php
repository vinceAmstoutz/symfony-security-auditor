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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Exception;

use RuntimeException;

/** @internal not part of the BC promise, see docs/versioning.md */
final class UnsupportedOutputFormatException extends RuntimeException
{
    public static function forFormat(string $format): self
    {
        return new self(\sprintf('No report renderer is registered for output format "%s".', $format));
    }

    public static function forOutputFileWithoutExtension(string $outputFile): self
    {
        return new self(\sprintf('The output file "%s" has no extension to pick the report format from. Give it one (.html, .json, .sarif, .md or .xml) or choose the format with --format: console, executive, json, sarif, html, markdown, junit, github or github-comment.', $outputFile));
    }
}
