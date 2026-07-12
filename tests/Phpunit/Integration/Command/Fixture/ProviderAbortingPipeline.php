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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture;

use Override;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;

/**
 * Test fake — adds a single already-validated finding to the context and then
 * throws `NonTransientLLMFailureException`, so tests can exercise the
 * partial-report path `AuditCommand::handleProviderAbort()` takes with a
 * non-empty `AuditContext`, mirroring what a real provider failure mid-run
 * leaves behind.
 *
 * @internal scoped to AuditCommand provider-abort integration tests
 */
final readonly class ProviderAbortingPipeline implements PipelineInterface
{
    public function __construct(
        private Vulnerability $vulnerability,
    ) {}

    /**
     * @throws NonTransientLLMFailureException
     */
    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $auditContext->addVulnerability($this->vulnerability);

        throw NonTransientLLMFailureException::from(new RuntimeException('model retired'));
    }
}
