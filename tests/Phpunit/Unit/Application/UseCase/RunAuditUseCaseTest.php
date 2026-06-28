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

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\RecordingStage;

final class RunAuditUseCaseTest extends TestCase
{
    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/usecase_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws AuditAbortedByBudgetException
     */
    public function test_it_runs_pipeline_against_the_audit_context(): void
    {
        $recordingStage = new RecordingStage();
        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingStage), new NullLogger());

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertCount(1, $recordingStage->processedAuditIds);
        self::assertSame($auditReport->auditId(), $recordingStage->processedAuditIds[0]);
    }

    /**
     * @throws AuditAbortedByBudgetException
     */
    public function test_it_logs_starting_audit_with_project_path(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $runAuditUseCase = new RunAuditUseCase($this->makePipeline(), $logger);
        $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(
            ['Starting audit', ['project' => $this->tmpDir, 'scan_paths' => [], 'cache_bypassed' => false, 'diff_since_ref' => null]],
            $infoLogs[0],
        );
    }

    /**
     * @throws AuditAbortedByBudgetException
     */
    public function test_it_marks_the_audit_context_as_cache_bypassed_when_requested(): void
    {
        $recordingStage = new RecordingStage();
        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingStage), new NullLogger());

        $runAuditUseCase->execute($this->tmpDir, [], true);

        self::assertSame([true], $recordingStage->observedCacheBypassed);
    }

    /**
     * @throws AuditAbortedByBudgetException
     */
    public function test_it_passes_scan_paths_to_the_pipeline_via_audit_context(): void
    {
        $recordingStage = new RecordingStage();
        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingStage), new NullLogger());

        $runAuditUseCase->execute($this->tmpDir, ['apps/api/src']);

        self::assertSame([['apps/api/src']], $recordingStage->observedScanPaths);
    }

    /**
     * @throws AuditAbortedByBudgetException
     */
    public function test_it_logs_audit_complete_with_exact_context(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $runAuditUseCase = new RunAuditUseCase($this->makePipeline(), $logger);
        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        $completeLog = array_values(array_filter($infoLogs, static fn (array $e): bool => 'Audit complete' === $e[0]))[0];
        self::assertSame($auditReport->auditId(), $completeLog[1]['audit_id']);
        self::assertSame($auditReport->riskLevel(), $completeLog[1]['risk_level']);
        self::assertSame(0, $completeLog[1]['vulnerabilities']);
        self::assertIsFloat($completeLog[1]['duration']);
    }

    private function makePipeline(?StageInterface $stage = null): AuditPipeline
    {
        return new AuditPipeline($stage instanceof StageInterface ? [$stage] : [], new NullLogger());
    }
}
