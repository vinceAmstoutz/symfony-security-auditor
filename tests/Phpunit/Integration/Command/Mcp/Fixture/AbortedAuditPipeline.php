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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp\Fixture;

use Override;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

/**
 * Test fake — a run that does what the given pipeline does, then stops on the
 * given failure, as a pipeline does when the budget runs out or the provider
 * fails after some findings were collected.
 *
 * @internal scoped to the MCP audit tool integration tests
 */
final readonly class AbortedAuditPipeline implements PipelineInterface
{
    public function __construct(
        private Throwable $throwable,
        private PipelineInterface $pipeline,
    ) {}

    /**
     * @throws InvalidProjectFileException
     * @throws Throwable
     */
    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $this->pipeline->process($auditContext);

        throw $this->throwable;
    }
}
