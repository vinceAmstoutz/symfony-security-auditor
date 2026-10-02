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

use Mcp\Exception\ToolCallException;
use Symfony\Component\Filesystem\Path;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\AuditWithoutVerdictException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilterInterface;

/** @internal not part of the BC promise — the MCP tool *name* (`audit`) is public, but the PHP class itself is for internal use only. */
final readonly class AuditTool
{
    public function __construct(
        private RunAuditUseCase $runAuditUseCase,
        private ReportRendererInterface $reportRenderer,
        private AuditedProjectPathHolder $auditedProjectPathHolder,
        private BaselineProcessorInterface $baselineProcessor,
        private FindingTypeFilterInterface $findingTypeFilter,
        private ReviewerFeedbackHolder $reviewerFeedbackHolder,
    ) {}

    /**
     * `mcp/sdk` answers a tool that throws anything but its own
     * `ToolCallException` with a bare "Error while executing tool", so every
     * failure — a relative path, an exhausted budget, a refused credential, a
     * run with no verdict — is rethrown as one, and its reason reaches the
     * client that asked.
     *
     * @throws ToolCallException
     */
    public function audit(string $path): string
    {
        try {
            return $this->reportRenderer->render($this->auditReport($this->canonicalPath($path)));
        } catch (Throwable $throwable) {
            throw $this->toolCallFailure($throwable);
        }
    }

    private function toolCallFailure(Throwable $throwable): ToolCallException
    {
        return new ToolCallException($throwable->getMessage(), previous: $throwable);
    }

    /**
     * Runs the audit as `audit:run` does without options: the configured
     * baseline's reasons reach the reviewer and the findings it accepts skip
     * the reviewer and leave the report, the muted finding types leave it too,
     * and a run with no verdict returns no report.
     *
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws AuditWithoutVerdictException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    private function auditReport(string $projectPath): AuditReport
    {
        $this->reviewerFeedbackHolder->set($this->baselineProcessor->feedback(null));

        $auditReport = $this->findingTypeFilter->apply(
            $this->runAuditUseCase->execute($projectPath, acceptedFingerprints: $this->baselineProcessor->acceptedFingerprints(null)),
        );
        $this->assertVerdict($auditReport);

        return $this->baselineProcessor->apply($auditReport, null)->report;
    }

    /**
     * `audit:run` fails a run whose scan found no file, or that analyzed none
     * of its files: a SAFE report there vouches for code nobody read.
     *
     * @throws AuditWithoutVerdictException
     */
    private function assertVerdict(AuditReport $auditReport): void
    {
        if (0 === $auditReport->filesDiscovered()) {
            throw AuditWithoutVerdictException::forNoFileDiscovered($auditReport->projectPath());
        }

        if ($auditReport->analyzedNoFile()) {
            throw AuditWithoutVerdictException::forNoFileAnalyzed($auditReport->projectPath(), $auditReport->filesScanned());
        }
    }

    /**
     * @throws InvalidProjectPathException
     */
    private function canonicalPath(string $path): string
    {
        if (!Path::isAbsolute($path)) {
            throw InvalidProjectPathException::forNonAbsolutePath($path);
        }

        $canonicalPath = Path::canonicalize($path);
        $this->auditedProjectPathHolder->set($canonicalPath);

        return $canonicalPath;
    }
}
