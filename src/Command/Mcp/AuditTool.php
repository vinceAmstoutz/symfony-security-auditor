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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp;

use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;

/** @internal not part of the BC promise — the MCP tool *name* (`audit`) is public, but the PHP class itself is for internal use only. */
final readonly class AuditTool
{
    public function __construct(
        private RunAuditUseCase $runAuditUseCase,
        private ReportRendererInterface $reportRenderer,
        private AuditedProjectPathHolder $auditedProjectPathHolder,
    ) {}

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidProjectPathException
     * @throws InvalidTokenUsageException
     */
    public function audit(string $path): string
    {
        if (!Path::isAbsolute($path)) {
            throw InvalidProjectPathException::forNonAbsolutePath($path);
        }

        $canonicalPath = Path::canonicalize($path);
        $this->auditedProjectPathHolder->set($canonicalPath);

        return $this->reportRenderer->render($this->runAuditUseCase->execute($canonicalPath));
    }
}
