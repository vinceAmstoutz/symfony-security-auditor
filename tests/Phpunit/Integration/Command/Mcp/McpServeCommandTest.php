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
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\AuditTool;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServeCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServerFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp\Fixture\PreloadedStdioTransportFactory;

final class McpServeCommandTest extends TestCase
{
    private string $projectPath;

    private PreloadedStdioTransportFactory $preloadedStdioTransportFactory;

    #[Override]
    protected function setUp(): void
    {
        $this->projectPath = sys_get_temp_dir().'/ssa-mcp-cmd-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->projectPath);
        $this->preloadedStdioTransportFactory = new PreloadedStdioTransportFactory([
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}',
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            \sprintf('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"audit","arguments":{"path":%s}}}', json_encode($this->projectPath, \JSON_THROW_ON_ERROR)),
        ]);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectPath);
    }

    public function test_it_reports_success_after_serving(): void
    {
        self::assertSame(Command::SUCCESS, (new CommandTester($this->command()))->execute([]));
    }

    public function test_it_serves_the_audit_tool_over_the_transport(): void
    {
        (new CommandTester($this->command()))->execute([]);

        $output = $this->preloadedStdioTransportFactory->capturedOutput();

        self::assertStringContainsString('AUDIT-', $output);
    }

    private function command(): McpServeCommand
    {
        $mcpServerFactory = new McpServerFactory(
            new AuditTool(new RunAuditUseCase(self::createStub(PipelineInterface::class), new NullLogger()), new JsonReportRenderer()),
            new ReportPackage(),
        );

        return new McpServeCommand($mcpServerFactory, $this->preloadedStdioTransportFactory);
    }
}
