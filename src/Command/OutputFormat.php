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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Filesystem\Path;

/** @internal not part of the BC promise: the enum *values* (`console`, `executive`, `json`, `sarif`, `html`, `markdown`, `junit`, `github`, `github-comment`) are part of the CLI contract, but the PHP enum itself is for internal use only. */
enum OutputFormat: string
{
    case Console = 'console';
    case Executive = 'executive';
    case Json = 'json';
    case Sarif = 'sarif';
    case Html = 'html';
    case Markdown = 'markdown';
    case Junit = 'junit';
    case GithubAnnotations = 'github';
    case GithubComment = 'github-comment';

    /**
     * Returns the format an output file's extension names, null for any other file.
     */
    public static function ofOutputFile(?string $outputFile): ?self
    {
        return match (null === $outputFile ? '' : Path::getExtension($outputFile, true)) {
            'html', 'htm' => self::Html,
            'json' => self::Json,
            'sarif' => self::Sarif,
            'md' => self::Markdown,
            'xml' => self::Junit,
            default => null,
        };
    }
}
