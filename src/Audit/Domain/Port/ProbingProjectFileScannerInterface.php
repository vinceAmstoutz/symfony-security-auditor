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

/**
 * Opt-in companion of {@see ProjectFileScannerInterface} for a scanner that can
 * tell whether its configured scan reaches a file without reading one: the
 * command line asks it of a directory holding no `composer.json` before it
 * decides which project to audit. A scanner without it is asked through a
 * whole scan.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ProbingProjectFileScannerInterface extends ProjectFileScannerInterface
{
    /**
     * Whether {@see ProjectFileScannerInterface::scan()} would reach a file in
     * the project, answered at the first one it meets, which is neither read
     * nor scrubbed.
     */
    public function reachesAFile(string $projectPath): bool;
}
