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

    public function description(): string
    {
        return match ($this) {
            self::TooLarge => 'it is larger than the scan size limit (scan.max_file_size_kb)',
            self::Unreadable => 'it could not be read',
        };
    }
}
