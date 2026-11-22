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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use function Symfony\Component\String\b;

/**
 * Puts a file path the LLM echoes, free text, in a form comparable with a
 * project file's, so a leading `./` does not keep a finding from its file.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class EchoedFilePath
{
    public static function normalize(string $path): string
    {
        return str_starts_with($path, './') ? substr($path, 2) : $path;
    }

    /**
     * Returns the comparable forms of the project file `$relativePath`. A path
     * names it exactly when its own comparable form is one of them.
     *
     * @return array{string, string}
     */
    public static function projectFileForms(string $relativePath, string $projectPath): array
    {
        return [self::comparable($relativePath), self::comparable(\sprintf('%s/%s', $projectPath, $relativePath))];
    }

    /**
     * Returns the path on forward slashes without a leading `./` or `/`.
     */
    public static function comparable(string $path): string
    {
        return b($path)->replace('\\', '/')->replaceMatches('#^(?:\./|/)+#', '')->toString();
    }
}
