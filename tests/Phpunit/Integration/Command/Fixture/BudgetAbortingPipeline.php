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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

/**
 * Test fake — adds a single already-validated finding to the context and then
 * throws `BudgetExceededException`, so tests can exercise the partial-report
 * path `AuditCommand::handleBudgetAbort()` takes with a non-empty
 * `AuditContext`, mirroring what a real budget abort mid-run leaves behind.
 *
 * @internal scoped to AuditCommand budget-abort integration tests
 */
final readonly class BudgetAbortingPipeline implements PipelineInterface
{
    public function __construct(
        private Vulnerability $vulnerability,
    ) {}

    /**
     * @throws BudgetExceededException
     */
    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $auditContext->addVulnerability($this->vulnerability);

        throw BudgetExceededException::forCost(1.5, 1.0);
    }
}
