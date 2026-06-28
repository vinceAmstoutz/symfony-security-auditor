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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;

/**
 * Test fake — always throws to verify cache writes never happen on failure.
 *
 * @internal scoped to LockfileHashedAdvisoryCacheTest
 */
final class ThrowingComposerAuditRunner implements ComposerAuditRunnerInterface
{
    #[Override]
    public function run(string $projectPath): string
    {
        throw AdvisorySourceUnavailableException::forFailedProcess($projectPath, 'inner exploded');
    }
}
