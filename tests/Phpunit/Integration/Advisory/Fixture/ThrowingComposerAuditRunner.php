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

use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;

/**
 * Test fake — always throws to verify cache writes never happen on failure.
 *
 * @internal scoped to LockfileHashedAdvisoryCacheTest
 */
final class ThrowingComposerAuditRunner implements ComposerAuditRunnerInterface
{
    public function run(string $projectPath): string
    {
        throw new RuntimeException('inner exploded');
    }
}
