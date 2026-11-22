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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;

/**
 * Runs `composer audit --format=json --locked` against a project path.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface ComposerAuditRunnerInterface
{
    /**
     * @throws AdvisorySourceUnavailableException when composer is missing, the
     *                                            project has no lock file or
     *                                            the process emits no usable JSON
     */
    public function run(string $projectPath): string;
}
