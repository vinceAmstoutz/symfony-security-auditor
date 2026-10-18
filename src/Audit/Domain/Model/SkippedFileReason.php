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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * Why a scan left a file it matched out of the files to analyze: nothing of it
 * reaches the attacker, so the run cannot vouch for it.
 */
enum SkippedFileReason: string
{
    case TooLarge = 'too_large';
    case Unreadable = 'unreadable';
    case AmbiguousName = 'ambiguous_name';
    case AmbiguousContent = 'ambiguous_content';
    case Symlink = 'symlink';

    public function description(): string
    {
        return match ($this) {
            self::TooLarge => 'it is larger than the scan size limit (scan.max_file_size_kb)',
            self::Unreadable => 'it could not be read',
            self::AmbiguousName => "its name is the same as another file's once the bytes that are not valid UTF-8 are replaced",
            self::AmbiguousContent => 'its content mixes bytes that are not valid UTF-8 with the characters they are replaced with, so two different names in it could read as one',
            self::Symlink => 'it is a symbolic link, which the scan never follows',
        };
    }

    /**
     * A file left out for its size, because it could not be read or because
     * it is a symbolic link was dropped silently before, and nothing gates on it; a file that cannot be
     * named or read back one way only could hide code, so the run cannot
     * pass as complete.
     */
    public function leavesTheRunIncomplete(): bool
    {
        return match ($this) {
            self::TooLarge, self::Unreadable, self::Symlink => false,
            self::AmbiguousName, self::AmbiguousContent => true,
        };
    }
}
