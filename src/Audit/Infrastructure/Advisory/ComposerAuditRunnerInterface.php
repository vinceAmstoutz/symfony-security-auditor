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
 * Adapter port for invoking `composer audit --format=json --locked` against an
 * arbitrary project path. Split from the database implementation so we can stub
 * the shell-out in unit tests and swap to other audit sources later.
 */
interface ComposerAuditRunnerInterface
{
    /**
     * @throws AdvisorySourceUnavailableException when composer is missing, the
     *                                            project has no lock file, or
     *                                            the process otherwise fails to
     *                                            emit a usable JSON document
     */
    public function run(string $projectPath): string;
}
