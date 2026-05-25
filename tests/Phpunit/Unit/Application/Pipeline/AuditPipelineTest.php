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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline;

use ArrayIterator;
use Closure;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture\RecordingProgressReporter;

final class AuditPipelineTest extends TestCase
{
    private string $tmpDir;

    public function test_it_processes_all_stages_in_order(): void
    {
        $callOrder = [];

        $stage1 = $this->createNamedStage('ingestion', static function () use (&$callOrder): void {
            $callOrder[] = 'ingestion';
        });

        $stage2 = $this->createNamedStage('mapping', static function () use (&$callOrder): void {
            $callOrder[] = 'mapping';
        });

        $stage3 = $this->createNamedStage('audit', static function () use (&$callOrder): void {
            $callOrder[] = 'audit';
        });

        $auditPipeline = new AuditPipeline([$stage1, $stage2, $stage3], new NullLogger());

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertSame(['ingestion', 'mapping', 'audit'], $callOrder);
    }

    public function test_it_exposes_injected_stages(): void
    {
        $stage = $this->createNamedStage('test', static function (): void {});
        $auditPipeline = new AuditPipeline([$stage], new NullLogger());

        self::assertCount(1, $auditPipeline->stages());
    }

    public function test_it_processes_with_no_stages_without_error(): void
    {
        $auditPipeline = new AuditPipeline([], new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_each_stage_receives_the_same_context(): void
    {
        $receivedContexts = [];

        $stage1 = $this->createNamedStage('ingestion', static function (AuditContext $auditContext) use (&$receivedContexts): void {
            $receivedContexts[] = $auditContext;
        });
        $stage2 = $this->createNamedStage('mapping', static function (AuditContext $auditContext) use (&$receivedContexts): void {
            $receivedContexts[] = $auditContext;
        });

        $auditPipeline = new AuditPipeline([$stage1, $stage2], new NullLogger());

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertCount(2, $receivedContexts);
        self::assertSame($auditContext, $receivedContexts[0]);
        self::assertSame($auditContext, $receivedContexts[1]);
    }

    public function test_it_logs_pipeline_start_info(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $auditPipeline = new AuditPipeline([], $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertSame('Starting audit pipeline', $infoLogs[0][0]);
        self::assertSame($auditContext->auditId(), $infoLogs[0][1]['audit_id']);
        self::assertSame([], $infoLogs[0][1]['stages']);
    }

    public function test_it_logs_pipeline_start_stages_as_array_of_strings(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $stage = $this->createNamedStage('my-stage', static function (): void {});
        $auditPipeline = new AuditPipeline([$stage], $logger);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        $startLog = array_values(array_filter($infoLogs, static fn (array $e): bool => 'Starting audit pipeline' === $e[0]))[0];
        self::assertSame(['my-stage'], $startLog[1]['stages']);
    }

    public function test_it_logs_pipeline_complete_info(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $auditPipeline = new AuditPipeline([], $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        $completeLog = array_values(array_filter($infoLogs, static fn (array $e): bool => 'Pipeline complete' === $e[0]))[0];
        self::assertSame($auditContext->auditId(), $completeLog[1]['audit_id']);
        self::assertSame(0, $completeLog[1]['vulnerabilities_found']);
        self::assertSame(0, $completeLog[1]['validated']);
    }

    public function test_it_logs_stage_running_info_for_each_stage(): void
    {
        $logger = self::createStub(LoggerInterface::class);

        $infoLogs = [];
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $stage = $this->createNamedStage('test-stage', static function (): void {});
        $auditPipeline = new AuditPipeline([$stage], $logger);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        $messages = array_column($infoLogs, 0);
        self::assertContains('Running stage: test-stage', $messages);
        self::assertContains('Stage "test-stage" completed', $messages);

        $runningLog = array_values(array_filter($infoLogs, static fn (array $e): bool => 'Running stage: test-stage' === $e[0]))[0];
        self::assertSame($auditContext->auditId(), $runningLog[1]['audit_id']);

        $completedLog = array_values(array_filter($infoLogs, static fn (array $e): bool => 'Stage "test-stage" completed' === $e[0]))[0];
        self::assertSame($auditContext->auditId(), $completedLog[1]['audit_id']);
        self::assertIsFloat($completedLog[1]['elapsed_seconds']);
        self::assertGreaterThanOrEqual(0.0, $completedLog[1]['elapsed_seconds']);
        self::assertLessThan(60.0, $completedLog[1]['elapsed_seconds']);
    }

    public function test_it_reports_pipeline_start_and_completion_events_to_the_progress_reporter(): void
    {
        $recordingProgressReporter = new RecordingProgressReporter();

        $stage = $this->createNamedStage('s', static function (): void {});
        $auditPipeline = new AuditPipeline([$stage], new NullLogger(), $recordingProgressReporter);
        $auditPipeline->process(AuditContext::forProject($this->tmpDir));

        $eventNames = array_column($recordingProgressReporter->events, 0);
        self::assertContains('pipeline.started', $eventNames);
        self::assertContains('pipeline.completed', $eventNames);
    }

    public function test_it_reports_stage_started_and_completed_events_for_each_stage(): void
    {
        $recordingProgressReporter = new RecordingProgressReporter();

        $stage = $this->createNamedStage('mapping', static function (): void {});
        $auditPipeline = new AuditPipeline([$stage], new NullLogger(), $recordingProgressReporter);
        $auditPipeline->process(AuditContext::forProject($this->tmpDir));

        $stageStarts = array_values(array_filter($recordingProgressReporter->events, static fn (array $e): bool => 'stage.started' === $e[0]));
        $stageCompletes = array_values(array_filter($recordingProgressReporter->events, static fn (array $e): bool => 'stage.completed' === $e[0]));

        self::assertCount(1, $stageStarts);
        self::assertSame('mapping', $stageStarts[0][1]['stage']);
        self::assertCount(1, $stageCompletes);
        self::assertSame('mapping', $stageCompletes[0][1]['stage']);
    }

    public function test_it_defaults_to_a_silent_progress_reporter_when_none_is_injected(): void
    {
        // No reporter argument — should not throw and not require external wiring.
        $stage = $this->createNamedStage('s', static function (): void {});
        $auditPipeline = new AuditPipeline([$stage], new NullLogger());

        $auditPipeline->process(AuditContext::forProject($this->tmpDir));

        self::assertCount(1, $auditPipeline->stages());
    }

    public function test_it_accepts_iterable_stages_from_iterator(): void
    {
        $callOrder = [];
        $stage1 = $this->createNamedStage('a', static function () use (&$callOrder): void {
            $callOrder[] = 'a';
        });
        $stage2 = $this->createNamedStage('b', static function () use (&$callOrder): void {
            $callOrder[] = 'b';
        });

        $auditPipeline = new AuditPipeline(new ArrayIterator([$stage1, $stage2]), new NullLogger());

        $auditPipeline->process(AuditContext::forProject($this->tmpDir));

        self::assertSame(['a', 'b'], $callOrder);
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/pipeline_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    private function createNamedStage(string $name, Closure $callback): StageInterface
    {
        return new class($name, $callback) implements StageInterface {
            public function __construct(
                private readonly string $stageName,
                private readonly Closure $callback,
            ) {}

            public function process(AuditContext $auditContext): void
            {
                ($this->callback)($auditContext);
            }

            public function name(): string
            {
                return $this->stageName;
            }
        };
    }
}
