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

/**
 * Test fake — returns a configurable JSON payload and counts how many times
 * the cache delegated to it.
 *
 * @internal scoped to LockfileHashedAdvisoryCacheTest
 */
final class RecordingComposerAuditRunner implements ComposerAuditRunnerInterface
{
    public int $callCount = 0;

    public function __construct(public string $payload) {}

    /**
     * @throws void
     */
    #[Override]
    public function run(string $projectPath): string
    {
        ++$this->callCount;

        return $this->payload;
    }
}
