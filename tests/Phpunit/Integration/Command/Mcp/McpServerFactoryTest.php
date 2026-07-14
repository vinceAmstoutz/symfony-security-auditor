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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\AuditTool;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServerFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp\Fixture\PreloadedStdioTransportFactory;

final class McpServerFactoryTest extends TestCase
{
    private string $projectPath;

    #[Override]
    protected function setUp(): void
    {
        $this->projectPath = sys_get_temp_dir().'/ssa-mcp-factory-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->projectPath);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectPath);
    }

    public function test_it_advertises_the_server_under_the_auditor_name(): void
    {
        self::assertStringContainsString('"name":"symfony-security-auditor"', $this->converse());
    }

    public function test_it_registers_the_audit_tool_with_its_description(): void
    {
        $output = $this->converse();

        self::assertStringContainsString('"name":"audit"', $output);
        self::assertStringContainsString('return the JSON report', $output);
    }

    public function test_it_declares_a_required_string_path_argument_on_the_audit_tool(): void
    {
        $output = $this->converse();

        self::assertStringContainsString('"path":{"type":"string"', $output);
        self::assertStringContainsString('"required":["path"]', $output);
    }

    public function test_calling_the_audit_tool_runs_an_audit_and_returns_a_report(): void
    {
        $output = $this->converse();

        self::assertStringContainsString('"isError":false', $output);
        self::assertStringContainsString('AUDIT-', $output);
    }

    private function converse(): string
    {
        $server = (new McpServerFactory(
            new AuditTool(new RunAuditUseCase(self::createStub(PipelineInterface::class), new NullLogger()), new JsonReportRenderer()),
            new ReportPackage(),
        ))->create();

        $preloadedStdioTransportFactory = new PreloadedStdioTransportFactory([
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}',
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
            \sprintf('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"audit","arguments":{"path":%s}}}', json_encode($this->projectPath, \JSON_THROW_ON_ERROR)),
        ]);

        $server->run($preloadedStdioTransportFactory->create());

        return $preloadedStdioTransportFactory->capturedOutput();
    }
}
