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
 * Optional companion of {@see ProjectFileScannerInterface}, checked with
 * `instanceof`: tells whether the configured scan reaches a file without
 * reading one. Without it, a whole scan answers.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
