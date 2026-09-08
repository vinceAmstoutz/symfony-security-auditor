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

namespace VinceAmstoutz\SecurityAuditor\Command\Mcp;

use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Exception\AuditAbortedByProviderException;
use VinceAmstoutz\SecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SecurityAuditor\Command\Exception\InvalidProjectPathException;

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
