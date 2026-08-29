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
 * Deterministic, zero-token pre-scanner tagging files with risk markers before
 * the LLM sees them. Three uses:
 *
 *  1. Markers go into the attacker prompt so the LLM starts at concrete
 *     locations instead of re-discovering smells.
 *  2. Marker-bearing files can be batched first, improving signal-per-token.
 *  3. In lean mode, files with zero markers are skipped entirely.
 *
 * Implementations MUST be pure and fast: no I/O beyond the already-loaded
 * `ProjectFile::content()`, no network calls.
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
