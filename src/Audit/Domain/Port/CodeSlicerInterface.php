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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Trims a file to its security-relevant lines before it reaches the LLM: each
 * retained line keeps its 1-based number and each elided run collapses into
 * one placeholder.
 *
 * Implementations MUST be pure (no I/O, no clock) and idempotent and MUST
 * NEVER renumber a retained line: findings cite the original line numbers.
 */
interface CodeSlicerInterface
{
    public function slice(ProjectFile $projectFile): string;
}
