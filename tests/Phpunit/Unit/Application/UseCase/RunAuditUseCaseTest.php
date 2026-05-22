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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

final class RunAuditUseCaseTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/usecase_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_it_returns_audit_report(): void
    {
        $pipeline = self::createStub(PipelineInterface::class);
        $runAuditUseCase = new RunAuditUseCase($pipeline, new NullLogger());

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertInstanceOf(AuditReport::class, $auditReport);
    }

    public function test_it_calls_pipeline_process(): void
    {
        $pipeline = $this->createMock(PipelineInterface::class);
        $pipeline->expects(self::once())->method('process');

        $runAuditUseCase = new RunAuditUseCase($pipeline, new NullLogger());
        $runAuditUseCase->execute($this->tmpDir);
    }

    public function test_it_logs_starting_audit_with_project_path(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $pipeline = self::createStub(PipelineInterface::class);
        $runAuditUseCase = new RunAuditUseCase($pipeline, $logger);
        $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(['Starting audit', ['project' => $this->tmpDir]], $infoLogs[0]);
    }

    public function test_it_logs_audit_complete_with_exact_context(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $pipeline = self::createStub(PipelineInterface::class);
        $runAuditUseCase = new RunAuditUseCase($pipeline, $logger);
        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        $completeLog = array_values(array_filter($infoLogs, static fn (array $e): bool => 'Audit complete' === $e[0]))[0];
        self::assertSame($auditReport->auditId(), $completeLog[1]['audit_id']);
        self::assertSame($auditReport->riskLevel(), $completeLog[1]['risk_level']);
        self::assertSame(0, $completeLog[1]['vulnerabilities']);
        self::assertIsFloat($completeLog[1]['duration']);
    }
}
