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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;
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
     * @throws InvalidProjectPathException
     * @throws InvalidTokenUsageException
     */
    public function test_it_audits_the_given_path_and_returns_the_rendered_json_report(): void
    {
        $auditTool = new AuditTool($this->runAuditUseCase(), new JsonReportRenderer(), $this->auditedProjectPathHolder());

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertSame($this->projectPath, $report['project']);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidProjectPathException
     * @throws InvalidTokenUsageException
     */
    public function test_it_returns_the_report_as_rendered_by_the_report_renderer(): void
    {
        $renderer = self::createStub(ReportRendererInterface::class);
        $renderer->method('render')->willReturn('RENDERED-REPORT');

        $auditTool = new AuditTool($this->runAuditUseCase(), $renderer, $this->auditedProjectPathHolder());

        self::assertSame('RENDERED-REPORT', $auditTool->audit($this->projectPath));
    }

    /**
     * `ComposerAuditAdvisoryDatabase`, `SarifImportingPreScanner` and
     * `FilesystemTriageMemoryStore` all resolve the audited project through
     * `AuditedProjectPathHolder::path()`, which falls back to the bundle's own
     * `kernel.project_dir` when never `set()`. `AuditCommand` sets it from the
     * resolved CLI argument before running; the MCP entrypoint must do the
     * same for its own `path` argument, or those collaborators silently
     * resolve against the wrong project when the tool is invoked over MCP.
     *
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidProjectPathException
     * @throws InvalidTokenUsageException
     */
    public function test_it_sets_the_audited_project_path_holder_before_running_the_use_case(): void
    {
        $auditedProjectPathHolder = $this->auditedProjectPathHolder();
        $auditTool = new AuditTool($this->runAuditUseCase(), new JsonReportRenderer(), $auditedProjectPathHolder);

        $auditTool->audit($this->projectPath);

        self::assertSame($this->projectPath, $auditedProjectPathHolder->path());
    }

    /**
     * The MCP tool's own JSON schema documents `path` as "Absolute path to
     * the Symfony project directory to audit" but nothing enforced that
     * contract — unlike `AuditCommandInput::resolvedProjectPath()`, which
     * resolves a relative CLI argument against a known working directory.
     * An MCP tool call has no equivalent "current directory" concept to fall
     * back to, so a relative `path` is rejected rather than silently
     * resolved against the server process's own cwd.
     *
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidProjectPathException
     * @throws InvalidTokenUsageException
     */
    public function test_it_rejects_a_non_absolute_path(): void
    {
        $auditTool = new AuditTool($this->runAuditUseCase(), new JsonReportRenderer(), $this->auditedProjectPathHolder());

        $this->expectException(InvalidProjectPathException::class);
        $this->expectExceptionMessage('must be absolute');

        $auditTool->audit('relative/path');
    }

    /**
     * `AuditCommandInput::resolvedProjectPath()` canonicalizes an absolute
     * CLI argument via `Path::canonicalize()` before anything downstream
     * sees it; `AuditTool` must do the same for its own `path` argument so a
     * `..`-bearing MCP path resolves identically to the CLI path, keeping
     * `AuditedProjectPathHolder::path()` a stable cache/lookup key regardless
     * of entry point.
     *
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidProjectPathException
     * @throws InvalidTokenUsageException
     */
    public function test_it_canonicalizes_the_path_before_setting_the_holder_and_running(): void
    {
        $auditedProjectPathHolder = $this->auditedProjectPathHolder();
        $auditTool = new AuditTool($this->runAuditUseCase(), new JsonReportRenderer(), $auditedProjectPathHolder);

        $auditTool->audit($this->projectPath.'/nested/..');

        self::assertSame($this->projectPath, $auditedProjectPathHolder->path());
    }

    private function runAuditUseCase(): RunAuditUseCase
    {
        return new RunAuditUseCase(self::createStub(PipelineInterface::class), new NullLogger());
    }

    private function auditedProjectPathHolder(): AuditedProjectPathHolder
    {
        return new AuditedProjectPathHolder('/default/project/dir');
    }
}
