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

    public static function fromProcessFailure(string $ref, string $stderr, Throwable $throwable): self
    {
        $stderr = trim($stderr);

        return new self(\sprintf('git diff against "%s" failed: %s', $ref, '' !== $stderr ? $stderr : 'unknown error'), 0, $throwable);
    }

    /**
     * Covers a git process that never produced a determinate result at
     * all — a timeout or a process start failure — as opposed to
     * `forNonGitDirectory()`/`forUnknownRef()`, which report a git process
     * that ran fine and determinately answered "no".
     */
    public static function forProcessFailure(string $operation, Throwable $throwable): self
    {
        return new self(\sprintf('Could not %s: %s', $operation, $throwable->getMessage()), 0, $throwable);
    }
}
