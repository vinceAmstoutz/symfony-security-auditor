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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

use RuntimeException;
use Throwable;

final class GitChangedFilesUnavailableException extends RuntimeException
{
    public static function forNonGitDirectory(string $projectPath): self
    {
        return new self(\sprintf('Project path "%s" is not a git working tree; cannot resolve --since changes.', $projectPath));
    }

    public static function forUnknownRef(string $ref, string $projectPath): self
    {
        return new self(\sprintf('Git ref "%s" does not resolve in "%s". Fetch it or pick another ref (e.g. origin/main).', $ref, $projectPath));
    }

    public static function fromProcessFailure(string $ref, string $stderr, Throwable $previous): self
    {
        return new self(\sprintf('git diff against "%s" failed: %s', $ref, trim($stderr) ?: 'unknown error'), 0, $previous);
    }
}
