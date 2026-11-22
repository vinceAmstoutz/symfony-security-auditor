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
 * (`unserialize`, `|raw`, `csrf_protection: false`, a missing `setParameter`)
 * before the LLM sees them. The markers point the attacker prompt at concrete
 * lines, put marked files first and, in lean mode, leave unmarked files out.
 *
 * Implementations MUST be pure and fast: no I/O beyond the already-loaded
 * `ProjectFile::content()`.
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
