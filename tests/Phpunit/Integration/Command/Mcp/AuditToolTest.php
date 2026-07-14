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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\AuditTool;

final class AuditToolTest extends TestCase
{
    private string $projectPath;

    #[Override]
    protected function setUp(): void
    {
        $this->projectPath = sys_get_temp_dir().'/ssa-mcp-audit-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->projectPath);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectPath);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_audits_the_given_path_and_returns_the_rendered_json_report(): void
    {
        $auditTool = new AuditTool($this->runAuditUseCase(), new JsonReportRenderer());

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertSame($this->projectPath, $report['project']);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_returns_the_report_as_rendered_by_the_report_renderer(): void
    {
        $renderer = self::createStub(ReportRendererInterface::class);
        $renderer->method('render')->willReturn('RENDERED-REPORT');

        $auditTool = new AuditTool($this->runAuditUseCase(), $renderer);

        self::assertSame('RENDERED-REPORT', $auditTool->audit($this->projectPath));
    }

    private function runAuditUseCase(): RunAuditUseCase
    {
        return new RunAuditUseCase(self::createStub(PipelineInterface::class), new NullLogger());
    }
}
