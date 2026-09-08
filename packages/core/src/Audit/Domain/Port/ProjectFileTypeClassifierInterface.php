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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFileType;

/**
 * Decides what a discovered file *is*, which is the one piece of framework
 * knowledge the audit engine cannot infer for itself: everything downstream —
 * the chunker, the skill blocks, the access-control and form-binding maps —
 * switches on {@see ProjectFileType} and its
 * {@see ProjectFileType::archetype()}. Implement this to teach the auditor a
 * framework whose conventions differ from Symfony's.
 *
 * Implementations MUST be pure: classification is derived from the path and
 * content alone, with no I/O, so the same file always classifies the same way.
 */
interface ProjectFileTypeClassifierInterface
{
    /**
     * @param string $relativePath project-relative path, as {@see ProjectFile::relativePath()} reports it
     */
    public function classify(string $relativePath, string $content): ProjectFileType;

    /**
     * The vocabulary this profile can actually produce. Tools offer these as
     * filter values, so a project is never invited to filter on a type its own
     * framework has no concept of.
     *
     * @return list<ProjectFileType>
     */
    public function supportedTypes(): array;
}
