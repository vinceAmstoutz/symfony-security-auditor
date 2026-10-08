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
 * What one scan of a project came back with: the files to analyze and the
 * files it matched but had to leave out.
 */
final readonly class ProjectFileScan
{
    /**
     * @param list<ProjectFile> $files
     * @param list<SkippedFile> $skippedFiles
     */
    public function __construct(
        public array $files,
        public array $skippedFiles,
    ) {}
}
