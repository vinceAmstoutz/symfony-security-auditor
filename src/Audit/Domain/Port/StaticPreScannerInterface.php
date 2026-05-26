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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;

/**
 * Deterministic, zero-token pre-scanner that tags files with risk markers
 * (e.g. `unserialize`, `|raw`, `csrf_protection: false`, missing
 * `setParameter`) before the LLM ever sees them. Three uses:
 *
 *  1. Markers are injected into the attacker prompt so the LLM focuses on
 *     concrete locations instead of re-discovering smells.
 *  2. Files with markers can be batched ahead of files without markers,
 *     improving signal-per-token on the early chunks.
 *  3. In `lean mode`, files with zero markers can be skipped entirely —
 *     the biggest token saver on large codebases.
 *
 * Implementations MUST be pure and fast. No I/O beyond reading the
 * already-loaded `ProjectFile::content()`. No network calls.
 */
interface StaticPreScannerInterface
{
    /**
     * @param list<ProjectFile> $files
     *
     * @return list<RiskMarker>
     */
    public function scan(array $files): array;
}
