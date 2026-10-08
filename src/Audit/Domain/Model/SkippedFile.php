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
 * A file a scan matched and still left out of the files to analyze, and why.
 */
final readonly class SkippedFile
{
    public function __construct(
        public string $relativePath,
        public SkippedFileReason $reason,
    ) {}
}
