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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\ErrorHandler\BufferingLogger;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityDropReason;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ContextAwareAttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture\RecordingProgressReporter;

final class AttackerAgentTest extends TestCase
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    private string $tmpDir;

    /**
     * @param list<ProjectFile>                                                                                         $files
     * @param array{bypassCache?: bool, previousFindings?: list<Vulnerability>, rejectedFindings?: list<Vulnerability>} $overrides
     *
     * @return list<Vulnerability>
     */
    private function callAnalyze(AttackerAgentInterface $attackerAgent, array $files, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder, array $overrides = []): array
    {
        return $attackerAgent->analyze(
            new AttackerAnalysisRequest(
                $files,
                $symfonyMapping,
                $overrides['bypassCache'] ?? false,
                $overrides['previousFindings'] ?? [],
                $overrides['rejectedFindings'] ?? [],
            ),
            $coverageRecorder,
        );
    }

    public function test_lean_mode_skip_logs_counts_records_skipped_coverage_and_returns_empty(): void
    {
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $staticPreScanner = self::createStub(StaticPreScannerInterface::class);
        $staticPreScanner->method('scan')->willReturn([]);

        $bufferingLogger = new BufferingLogger();
        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $bufferingLogger, 'toolsEnabled' => false, 'staticPreScanner' => $staticPreScanner, 'leanMode' => true]);

        $coverageRecorder = new class implements CoverageRecorderInterface {
            /** @var list<string> */
            public array $statuses = [];

            public function recordCoverage(string $stage, string $filePath, string $status): void
            {
                $this->statuses[] = $status;
            }
        };

        $result = $attackerAgent->analyze(
            new AttackerAnalysisRequest([$this->makeFile('src/Controller/A.php'), $this->makeFile('src/Controller/B.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())),
            $coverageRecorder,
        );

        self::assertSame([], $result);
        self::assertSame(['skipped', 'skipped'], $coverageRecorder->statuses);

        $logs = $bufferingLogger->cleanLogs();
        self::assertSame(['files' => 2, 'markers' => 0], $this->contextOf($logs, 'Attacker agent skipped — lean mode filtered all files'));
        $messages = array_map(static function (mixed $entry): mixed {
            self::assertIsArray($entry);

            return $entry[1] ?? null;
        }, $logs);
        self::assertNotContains('Attacker agent starting analysis', $messages);
    }

    public function test_risk_markers_are_prepended_before_the_user_message(): void
    {
        $markers = [RiskMarker::create('src/Controller/A.php', 10, 'request_get', 'Request input read')];
        $staticPreScanner = self::createStub(StaticPreScannerInterface::class);
        $staticPreScanner->method('scan')->willReturn($markers);

        $captured = '';
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$captured): LLMResponse {
            $captured = $user;

            return LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
        });

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => new NullLogger(), 'toolsEnabled' => false, 'staticPreScanner' => $staticPreScanner]);

        $attackerAgent->analyze(new AttackerAnalysisRequest([$this->makeFile('src/Controller/A.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())), new NullCoverageRecorder());

        self::assertStringStartsWith((new AttackerContextPromptRenderer())->renderRiskMarkers($markers)."\n\n", $captured);
        self::assertStringContainsString('## Source Code', $captured);
    }

    public function test_previous_findings_are_prepended_before_the_user_message(): void
    {
        $previousFindings = [$this->makeVulnerabilityFor('src/Controller/A.php')];

        $captured = '';
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$captured): LLMResponse {
            $captured = $user;

            return LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
        });

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $attackerAgent->analyze(
            new AttackerAnalysisRequest([$this->makeFile('src/Controller/A.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), false, $previousFindings),
            new NullCoverageRecorder(),
        );

        self::assertStringStartsWith((new AttackerContextPromptRenderer())->renderPreviousFindings($previousFindings)."\n\n", $captured);
        self::assertStringContainsString('## Source Code', $captured);
    }

    public function test_rejected_findings_are_prepended_before_the_user_message_with_a_blank_line(): void
    {
        $rejectedFindings = [$this->makeVulnerabilityFor('src/Controller/Rejected.php')];

        $captured = '';
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$captured): LLMResponse {
            $captured = $user;

            return LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
        });

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $attackerAgent->analyze(
            new AttackerAnalysisRequest([$this->makeFile('src/Controller/A.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), false, [], $rejectedFindings),
            new NullCoverageRecorder(),
        );

        // Pins both the rejected-findings preamble AND the "\n\n" separator
        // before the rest of the message (no other preamble is present).
        self::assertStringStartsWith((new AttackerContextPromptRenderer())->renderRejectedFindings($rejectedFindings)."\n\n", $captured);
        self::assertStringContainsString('## Source Code', $captured);
    }

    public function test_it_sends_the_sliced_content_to_the_llm(): void
    {
        $codeSlicer = self::createStub(CodeSlicerInterface::class);
        $codeSlicer->method('slice')->willReturn("<?php\n// SLICED-MARKER");

        $captured = '';
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$captured): LLMResponse {
            $captured = $user;

            return LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
        });

        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                codeSlicer: $codeSlicer,
            ),
            new AttackerScanCollaborators(
                attackerCache: new NullAttackerCache(),
            ),
            new AttackerAnalysisSettings(),
            new NullLogger(),
        );

        $attackerAgent->analyze(new AttackerAnalysisRequest([$this->makeFile('src/Controller/A.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())), new NullCoverageRecorder());

        self::assertStringContainsString('SLICED-MARKER', $captured);
    }

    public function test_it_returns_empty_array_when_no_files(): void
    {
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $result = $this->callAnalyze($attackerAgent, [], $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_calls_llm_with_files_and_returns_vulnerabilities(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups(['controllers' => $files]),
            new AccessControlMap(),
        );

        $llmPayload = (string) json_encode([[
            'type' => 'broken_access_control',
            'severity' => 'critical',
            'title' => 'Missing access control',
            'description' => 'Controller exposes admin route without voter',
            'file_path' => 'src/Controller/UserController.php',
            'line_start' => 10,
            'line_end' => 20,
            'vulnerable_code' => 'public function adminAction()',
            'attack_vector' => 'Direct URL access',
            'proof' => 'GET /admin/users',
            'remediation' => 'Add #[IsGranted("ROLE_ADMIN")]',
            'confidence' => 0.9,
        ]]);

        $llmResponse = LLMResponse::of($llmPayload, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 200));

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, $symfonyMapping, new NullCoverageRecorder());

        self::assertCount(1, $vulnerabilities);
        self::assertSame('Missing access control', $vulnerabilities[0]->title());
    }

    public function test_it_handles_llm_json_parse_error_gracefully(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $llmResponse = LLMResponse::of('not valid json {{{', 'claude', 'end_turn', TokenUsageSnapshot::of(100, 10));

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $this->callAnalyze($attackerAgent, $files, $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_handles_llm_exception_gracefully(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willThrowException(new RuntimeException('API timeout'));

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $this->callAnalyze($attackerAgent, $files, $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_handles_empty_llm_response(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $llmResponse = LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(100, 0));

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $this->callAnalyze($attackerAgent, $files, $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_chunks_files_for_large_projects(): void
    {
        // Create 15 files (> CHUNK_SIZE of 10)
        $files = [];
        for ($i = 1; $i <= 15; ++$i) {
            $files[] = $this->makeFile(\sprintf('src/Service/Service%d.php', $i));
        }

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $llmResponse = LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(100, 10));

        $llmClient = $this->createMock(LLMClientInterface::class);
        // Should be called twice (ceil(15/10) = 2 chunks)
        $llmClient
            ->expects(self::exactly(2))
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $this->callAnalyze($attackerAgent, $files, $symfonyMapping, new NullCoverageRecorder());
    }

    public function test_it_accumulates_vulnerabilities_from_multiple_chunks(): void
    {
        $files = [];
        for ($i = 1; $i <= 12; ++$i) {
            $files[] = $this->makeFile(\sprintf('src/Service/Service%d.php', $i));
        }

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $chunk1Json = (string) json_encode([[
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => 'SQL Injection chunk 1',
            'description' => 'desc',
            'file_path' => 'src/Service/Service1.php',
            'line_start' => 10,
            'line_end' => 15,
            'vulnerable_code' => '$q',
            'attack_vector' => 'inject',
            'proof' => "' OR 1",
            'remediation' => 'fix',
            'confidence' => 0.9,
        ]]);

        $chunk2Json = (string) json_encode([[
            'type' => 'broken_access_control',
            'severity' => 'critical',
            'title' => 'BAC chunk 2',
            'description' => 'desc',
            'file_path' => 'src/Service/Service11.php',
            'line_start' => 20,
            'line_end' => 25,
            'vulnerable_code' => 'fn()',
            'attack_vector' => 'access',
            'proof' => 'GET /admin',
            'remediation' => 'fix',
            'confidence' => 0.8,
        ]]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('complete')
            ->willReturnOnConsecutiveCalls(
                LLMResponse::of($chunk1Json, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)),
                LLMResponse::of($chunk2Json, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)),
            );

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $this->callAnalyze($attackerAgent, $files, $symfonyMapping, new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertSame('SQL Injection chunk 1', $result[0]->title());
        self::assertSame('BAC chunk 2', $result[1]->title());
    }

    #[DataProvider('chunkPriorityCases')]
    public function test_it_orders_files_by_priority_in_chunks(string $higherPriorityPath, string $lowerPriorityPath): void
    {
        $capturedUserMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $sys, string $user) use (&$capturedUserMessages): LLMResponse {
                $capturedUserMessages[] = $user;

                return LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(100, 10));
            });

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $this->callAnalyze($attackerAgent,
            [$this->makeFile($lowerPriorityPath), $this->makeFile($higherPriorityPath)],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertCount(1, $capturedUserMessages);
        $posHigher = strpos($capturedUserMessages[0], basename($higherPriorityPath));
        $posLower = strpos($capturedUserMessages[0], basename($lowerPriorityPath));
        self::assertNotFalse($posHigher);
        self::assertNotFalse($posLower);
        self::assertLessThan($posLower, $posHigher);
    }

    /** @return iterable<string, array{string, string}> */
    public static function chunkPriorityCases(): iterable
    {
        // Each pair shares a feature name (User*) so the feature chunker keeps them in
        // the same chunk where attack-surface priority orders the files.
        yield 'controllers before voters' => ['src/Controller/UserController.php', 'src/Security/UserVoter.php'];
        yield 'voters before entities' => ['src/Security/UserVoter.php', 'src/Entity/User.php'];
        yield 'entities before repositories' => ['src/Entity/User.php', 'src/Repository/UserRepository.php'];
        yield 'repositories before forms' => ['src/Repository/UserRepository.php', 'src/Form/UserType.php'];
        yield 'forms before services' => ['src/Form/UserType.php', 'src/Service/UserHelper.php'];
        yield 'controllers before services' => ['src/Controller/UserController.php', 'src/Service/UserService.php'];
    }

    public function test_it_does_not_call_llm_when_no_files_and_returns_empty(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('info');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $result = $this->callAnalyze($attackerAgent, [], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame([], $result);
    }

    public function test_it_logs_info_when_starting_analysis_with_files(): void
    {
        $loggedMessages = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message) use (&$loggedMessages): void {
                $loggedMessages[] = $message;
            },
        );

        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertContains('Attacker agent starting analysis', $loggedMessages);
    }

    public function test_it_logs_error_with_json_parse_failure_message(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with('Failed to parse attacker agent JSON response', [
                'error' => 'Syntax error',
                'content_preview' => 'invalid json {{{',
            ]);

        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('invalid json {{{', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $result = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame([], $result);
    }

    public function test_it_truncates_long_content_in_parse_failure_log(): void
    {
        $errorLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug');
        $logger->method('error')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$errorLogs): void {
                $errorLogs[] = [$msg, $ctx];
            },
        );

        $longInvalidContent = str_repeat('x', self::PARSE_FAILURE_PREVIEW_BYTES * 2).' {{{';

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($longInvalidContent, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $this->callAnalyze($attackerAgent,
            [$this->makeFile('src/Controller/UserController.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertCount(1, $errorLogs);
        self::assertSame('Failed to parse attacker agent JSON response', $errorLogs[0][0]);
        $preview = $errorLogs[0][1]['content_preview'];
        self::assertIsString($preview);
        self::assertSame(self::PARSE_FAILURE_PREVIEW_BYTES, \strlen($preview));
        self::assertSame(str_repeat('x', self::PARSE_FAILURE_PREVIEW_BYTES), $preview);
    }

    public function test_it_logs_error_with_llm_call_failed_message_on_throwable(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with('Attacker agent LLM call failed', ['error' => 'Network error']);

        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new RuntimeException('Network error'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $result = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame([], $result);
    }

    public function test_it_logs_info_starting_analysis_with_exact_file_count(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $files = [$this->makeFile('src/Controller/UserController.php'), $this->makeFile('src/Entity/User.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame(['Attacker agent starting analysis', ['files' => 2, 'files_filtered_lean' => 0, 'markers' => 0, 'tools_enabled' => false, 'cache_bypassed' => false, 'previous_findings' => 0, 'rejected_findings' => 0]], $infoLogs[0]);
        self::assertSame(['Attacker agent complete', ['total_vulnerabilities' => 0, 'total_dropped_entries' => 0, 'dropped_by_reason' => []]], $infoLogs[1]);
    }

    public function test_it_aggregates_drop_counts_across_chunks_in_complete_log(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');
        $logger->method('warning');

        $files = [];
        for ($i = 1; $i <= 15; ++$i) {
            $files[] = $this->makeFile(\sprintf('src/Service/Service%d.php', $i));
        }

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('["not-an-array-entry", "another-bad-one"]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        $completeLog = $infoLogs[\count($infoLogs) - 1];
        self::assertSame('Attacker agent complete', $completeLog[0]);
        self::assertSame(0, $completeLog[1]['total_vulnerabilities']);
        self::assertSame(4, $completeLog[1]['total_dropped_entries']);
        self::assertSame([VulnerabilityDropReason::NON_ARRAY_ENTRY->value => 4], $completeLog[1]['dropped_by_reason']);
    }

    public function test_it_logs_debug_chunk_complete_with_exact_context(): void
    {
        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(2, $debugLogs);
        self::assertSame('Analyzing chunk 1/1', $debugLogs[0][0]);
        self::assertSame('Chunk analysis complete', $debugLogs[1][0]);
        self::assertSame(['chunk' => 1, 'found' => 0, 'dropped' => 0, 'total_so_far' => 0], $debugLogs[1][1]);
    }

    public function test_it_logs_debug_analyzing_chunk_with_one_based_index_for_multiple_chunks(): void
    {
        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $files = [];
        for ($i = 1; $i <= 15; ++$i) {
            $files[] = $this->makeFile(\sprintf('src/Service/Service%d.php', $i));
        }

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        $analyzingMessages = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => str_starts_with($entry[0], 'Analyzing chunk '),
        ));

        self::assertCount(2, $analyzingMessages);
        self::assertSame('Analyzing chunk 1/2', $analyzingMessages[0][0]);
        self::assertSame('Analyzing chunk 2/2', $analyzingMessages[1][0]);
    }

    public function test_it_does_not_log_error_for_empty_llm_response(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('error');
        $logger->method('info');
        $logger->method('debug');

        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 0)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger]);

        $result = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame([], $result);
    }

    public function test_it_serves_chunk_from_cache_and_skips_llm(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $cachedRaw = [[
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => 'Cached finding',
            'description' => 'cached',
            'file_path' => 'src/Controller/UserController.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.9,
        ]];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->expects(self::once())->method('get')->willReturn($cachedRaw);
        $cache->expects(self::never())->method('store');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $result = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertSame('Cached finding', $result[0]->title());
    }

    public function test_it_stores_chunk_results_in_cache_on_cache_miss(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $rawPayload = [[
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'Fresh finding',
            'description' => 'fresh',
            'file_path' => 'src/Controller/UserController.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.85,
        ]];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->method('get')->willReturn(null);
        $cache->expects(self::once())
            ->method('store')
            ->with(self::isArray(), $rawPayload);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode($rawPayload), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_it_filters_non_array_entries_out_of_cached_payload_as_a_list(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $firstFinding = [
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'First',
            'description' => 'x',
            'file_path' => 'src/Controller/UserController.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.85,
        ];
        $secondFinding = ['type' => 'sql_injection'] + $firstFinding;
        $secondFinding['title'] = 'Second';

        $mixedPayload = [$firstFinding, 'stray prose entry', $secondFinding];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->method('get')->willReturn(null);
        $cache->expects(self::once())
            ->method('store')
            ->with(self::isArray(), [$firstFinding, $secondFinding]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode($mixedPayload), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_it_stores_empty_array_in_cache_when_llm_returns_empty_response(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->method('get')->willReturn(null);
        $cache->expects(self::once())
            ->method('store')
            ->with(self::isArray(), []);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 0)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_bypass_cache_skips_cache_get_and_calls_llm(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->expects(self::never())->method('get');
        $cache->expects(self::never())->method('store');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['bypassCache' => true]);
    }

    public function test_bypass_cache_skips_cache_store_after_successful_llm_call(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $rawPayload = [[
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'Fresh finding',
            'description' => 'fresh',
            'file_path' => 'src/Controller/UserController.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.85,
        ]];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->expects(self::never())->method('get');
        $cache->expects(self::never())->method('store');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode($rawPayload), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $result = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['bypassCache' => true]);

        self::assertCount(1, $result);
    }

    public function test_it_records_coverage_analyzed_for_each_file_in_chunk_after_llm_call(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'file' => 'src/Controller/B.php', 'status' => 'analyzed'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_cached_for_each_file_in_chunk_on_cache_hit(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $cache = self::createStub(AttackerCacheInterface::class);
        $cache->method('get')->willReturn([]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'cached'],
                ['stage' => 'attacker', 'file' => 'src/Controller/B.php', 'status' => 'cached'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_errored_for_each_file_in_chunk_on_llm_exception(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new RuntimeException('API down'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'file' => 'src/Controller/B.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_aborted_when_llm_throws_budget_exceeded(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(BudgetExceededException::forCost(2.0, 1.0));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $budgetExceeded = false;
        try {
            $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The agent must rethrow BudgetExceededException.');

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'aborted'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_analyzed_when_llm_returns_empty_response(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 0)));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);

        self::assertSame(
            [['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'analyzed']],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_errored_for_each_file_in_chunk_on_json_parse_error(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('garbage {{{', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);

        self::assertSame(
            [['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'errored']],
            $auditContext->coverage(),
        );
    }

    public function test_it_dispatches_to_tool_loop_when_tools_enabled_and_factory_provided(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $factory = $this->createMock(ToolRegistryFactoryInterface::class);
        $factory->expects(self::once())->method('forProjectFiles')->with($files)->willReturn($toolRegistry);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->with(self::anything(), self::anything(), $toolRegistry, 8)
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['toolRegistryFactory' => $factory, 'toolsEnabled' => true]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_it_does_not_dispatch_to_tool_loop_when_tools_disabled(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        new ToolRegistry([], new NullLogger());
        $factory = $this->createMock(ToolRegistryFactoryInterface::class);
        $factory->expects(self::never())->method('forProjectFiles');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['toolRegistryFactory' => $factory, 'toolsEnabled' => false]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_it_uses_non_tool_path_when_factory_is_null_even_if_enabled(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['toolsEnabled' => true]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_it_passes_custom_max_tool_iterations_through_to_llm_client(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $factory = self::createStub(ToolRegistryFactoryInterface::class);
        $factory->method('forProjectFiles')->willReturn(new ToolRegistry([], new NullLogger()));

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->with(self::anything(), self::anything(), self::anything(), 13)
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['toolRegistryFactory' => $factory, 'toolsEnabled' => true, 'maxToolIterations' => 13]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_it_logs_tools_enabled_true_when_tools_active(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $factory = self::createStub(ToolRegistryFactoryInterface::class);
        $factory->method('forProjectFiles')->willReturn(new ToolRegistry([], new NullLogger()));

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('completeWithTools')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['logger' => $logger, 'toolRegistryFactory' => $factory, 'toolsEnabled' => true]);

        $this->callAnalyze($attackerAgent, [$this->makeFile('src/A.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        $startingLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Attacker agent starting analysis' === $entry[0],
        ));

        self::assertTrue($startingLogs[0][1]['tools_enabled']);
    }

    public function test_it_logs_info_with_file_count_when_chunk_served_from_cache(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $cache = self::createStub(AttackerCacheInterface::class);
        $cache->method('get')->willReturn([[
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => 'Cached',
            'description' => 'd',
            'file_path' => 'src/Controller/UserController.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.9,
        ]]);

        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $llmClient = self::createStub(LLMClientInterface::class);

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache, 'logger' => $logger]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        $cacheHitLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Attacker chunk served from cache' === $entry[0],
        ));

        self::assertCount(1, $cacheHitLogs);
        self::assertSame(['files' => 1], $cacheHitLogs[0][1]);
    }

    public function test_it_does_not_store_in_cache_when_llm_returns_invalid_json(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->method('get')->willReturn(null);
        $cache->expects(self::never())->method('store');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('garbage {{{', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_it_propagates_llm_provider_exception_and_records_errored_coverage(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new LLMProviderException('No provider found for model "claude-opus-4-7".'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $providerFailed = false;
        try {
            $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The agent must rethrow LLMProviderException.');

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_it_propagates_exhausted_transient_failure_and_records_errored_coverage(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(
                TransientLLMFailureException::afterExhaustedAttempts(3, new RuntimeException('Rate limit exceeded')),
            );

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $providerFailed = false;
        try {
            $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'TransientLLMFailureException (a LLMProviderException) must propagate.');

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/attacker_agent_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_it_injects_previous_findings_section_into_prompt_when_provided(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $previousFindings = [
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::INSECURE_DIRECT_OBJECT_REFERENCE, VulnerabilitySeverity::HIGH, 'IDOR earlier', 0.95),
                new CodeLocation('src/Controller/EarlierController.php', 42, 46),
                new VulnerabilityNarrative('desc', 'av', 'proof', 'fix'),
                'code',
            ),
        ];

        $attackerAgent = $this->makeAttackerAgent($llmClient);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => $previousFindings]);

        self::assertCount(1, $sentMessages);
        self::assertStringContainsString('Patterns Already Confirmed', $sentMessages[0]);
        self::assertStringContainsString('insecure_direct_object_reference', $sentMessages[0]);
        self::assertStringContainsString('src/Controller/EarlierController.php:42-46', $sentMessages[0]);
    }

    public function test_it_does_not_inject_previous_findings_section_when_empty(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $attackerAgent = $this->makeAttackerAgent($llmClient);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => []]);

        self::assertCount(1, $sentMessages);
        self::assertStringNotContainsString('Patterns Already Confirmed', $sentMessages[0]);
    }

    public function test_it_skips_cache_when_previous_findings_present(): void
    {
        $cache = self::createMock(AttackerCacheInterface::class);
        $cache->expects(self::never())->method('get');
        $cache->expects(self::never())->method('store');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $previousFindings = [
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'SQLi', 0.9),
                new CodeLocation('src/Repo.php', 1, 2),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
        ];

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => $previousFindings]);
    }

    public function test_it_injects_rejected_findings_section_into_prompt_when_provided(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $rejectedFindings = [$this->makeVulnerabilityFor('src/Controller/RejectedController.php')];

        $attackerAgent = $this->makeAttackerAgent($llmClient);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['rejectedFindings' => $rejectedFindings]);

        self::assertCount(1, $sentMessages);
        self::assertStringContainsString('Findings Already Rejected by the Reviewer', $sentMessages[0]);
        self::assertStringContainsString('src/Controller/RejectedController.php', $sentMessages[0]);
    }

    public function test_it_does_not_inject_rejected_findings_section_when_empty(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $attackerAgent = $this->makeAttackerAgent($llmClient);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $sentMessages);
        self::assertStringNotContainsString('Findings Already Rejected by the Reviewer', $sentMessages[0]);
    }

    public function test_it_skips_cache_when_rejected_findings_present(): void
    {
        $cache = self::createMock(AttackerCacheInterface::class);
        $cache->expects(self::never())->method('get');
        $cache->expects(self::never())->method('store');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $rejectedFindings = [$this->makeVulnerabilityFor('src/Controller/RejectedController.php')];

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['rejectedFindings' => $rejectedFindings]);
    }

    public function test_it_reads_cache_when_no_previous_findings(): void
    {
        $cache = self::createMock(AttackerCacheInterface::class);
        $cache->expects(self::once())->method('get')->willReturn(null);
        $cache->expects(self::once())->method('store');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_previous_findings_section_groups_locations_by_vulnerability_type(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $files = [$this->makeFile('src/Controller/UserController.php')];
        $previousFindings = [
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::INSECURE_DIRECT_OBJECT_REFERENCE, VulnerabilitySeverity::HIGH, 'IDOR 1', 0.95),
                new CodeLocation('src/Controller/A.php', 10, 15),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::INSECURE_DIRECT_OBJECT_REFERENCE, VulnerabilitySeverity::HIGH, 'IDOR 2', 0.95),
                new CodeLocation('src/Controller/B.php', 20, 25),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
        ];

        $attackerAgent = $this->makeAttackerAgent($llmClient);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => $previousFindings]);

        self::assertStringContainsString('src/Controller/A.php:10-15', $sentMessages[0]);
        self::assertStringContainsString('src/Controller/B.php:20-25', $sentMessages[0]);
    }

    public function test_it_injects_pre_scan_markers_section_when_scanner_reports_markers(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $scanner = new class implements StaticPreScannerInterface {
            public function scan(array $files): array
            {
                return [
                    RiskMarker::create(
                        'src/Service/Foo.php',
                        7,
                        'unserialize_call',
                        'unserialize() on payload',
                    ),
                ];
            }
        };

        $projectFile = ProjectFile::create('src/Service/Foo.php', '/app/src/Service/Foo.php', '<?php');
        $attackerAgent = $this->makeAttackerAgent($llmClient, ['staticPreScanner' => $scanner]);
        $this->callAnalyze($attackerAgent, [$projectFile], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $sentMessages);
        self::assertStringContainsString('Pre-Scan Risk Markers', $sentMessages[0]);
        self::assertStringContainsString('unserialize_call', $sentMessages[0]);
        self::assertStringContainsString('L7', $sentMessages[0]);
    }

    public function test_it_does_not_inject_markers_section_when_scanner_returns_empty(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $projectFile = ProjectFile::create('src/Service/Foo.php', '/app/src/Service/Foo.php', '<?php');
        $attackerAgent = $this->makeAttackerAgent($llmClient);
        $this->callAnalyze($attackerAgent, [$projectFile], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $sentMessages);
        self::assertStringNotContainsString('Pre-Scan Risk Markers', $sentMessages[0]);
    }

    public function test_lean_mode_skips_files_with_no_markers(): void
    {
        $llmClient = self::createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $projectFile = ProjectFile::create('src/Service/Clean.php', '/app/src/Service/Clean.php', '<?php class Clean {}');
        $attackerAgent = $this->makeAttackerAgent($llmClient, ['leanMode' => true]);

        $result = $this->callAnalyze($attackerAgent, [$projectFile], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame([], $result);
    }

    public function test_lean_mode_keeps_files_with_markers(): void
    {
        $sentMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use (&$sentMessages): LLMResponse {
                $sentMessages[] = $user;

                return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $scanner = new class implements StaticPreScannerInterface {
            public function scan(array $files): array
            {
                return [
                    RiskMarker::create(
                        'src/Service/Risky.php',
                        3,
                        'eval_call',
                        'eval() on dynamic input',
                    ),
                ];
            }
        };

        $projectFile = ProjectFile::create('src/Service/Risky.php', '/app/src/Service/Risky.php', '<?php');
        $clean = ProjectFile::create('src/Service/Clean.php', '/app/src/Service/Clean.php', '<?php');
        $attackerAgent = $this->makeAttackerAgent($llmClient, ['staticPreScanner' => $scanner, 'leanMode' => true]);

        $this->callAnalyze($attackerAgent, [$projectFile, $clean], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $sentMessages);
        self::assertStringContainsString('src/Service/Risky.php', $sentMessages[0]);
        self::assertStringNotContainsString('src/Service/Clean.php', $sentMessages[0]);
    }

    public function test_chunks_with_markers_still_consult_cache(): void
    {
        $cache = self::createMock(AttackerCacheInterface::class);
        $cache->expects(self::once())->method('get')->willReturn(null);
        $cache->expects(self::once())->method('store');

        $scanner = new class implements StaticPreScannerInterface {
            public function scan(array $files): array
            {
                return [
                    RiskMarker::create(
                        'src/Service/Risky.php',
                        1,
                        'p',
                        'd',
                    ),
                ];
            }
        };

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $projectFile = ProjectFile::create('src/Service/Risky.php', '/app/src/Service/Risky.php', '<?php');
        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache, 'staticPreScanner' => $scanner]);
        $this->callAnalyze($attackerAgent, [$projectFile], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_empty_llm_response_is_persisted_as_negative_cache_entry(): void
    {
        $cache = self::createMock(AttackerCacheInterface::class);
        $cache->expects(self::once())->method('get')->willReturn(null);
        $cache->expects(self::once())
            ->method('store')
            ->with(self::isArray(), []);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $projectFile = ProjectFile::create('src/Service/Clean.php', '/app/src/Service/Clean.php', '<?php');
        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);
        $this->callAnalyze($attackerAgent, [$projectFile], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php class Foo {}');
    }

    private function makeVulnerabilityFor(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'T', 0.9),
            new CodeLocation($filePath, 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }

    /**
     * @param array<mixed> $logs
     *
     * @return array<mixed>
     */
    private function contextOf(array $logs, string $message): array
    {
        foreach ($logs as $log) {
            self::assertIsArray($log);
            if ($message === ($log[1] ?? null)) {
                $context = $log[2] ?? [];
                self::assertIsArray($context);

                return $context;
            }
        }

        self::fail(\sprintf('No log entry with message "%s"', $message));
    }

    public function test_structured_collection_drives_findings_via_record_vulnerability_tool_calls(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
                self::assertTrue($toolRegistry->has('record_vulnerability'));
                $toolRegistry->execute('record_vulnerability', [
                    'type' => 'broken_access_control',
                    'severity' => 'high',
                    'title' => 'IDOR on user show',
                    'description' => 'No ownership check on the controller.',
                    'file_path' => 'src/Controller/UserController.php',
                    'line_start' => 12,
                    'line_end' => 14,
                    'vulnerable_code' => '$repo->find($id);',
                    'attack_vector' => 'GET /user/9999',
                    'proof' => '200 OK leaking other tenant data',
                    'remediation' => "Add denyAccessUnlessGranted('VIEW', \$user).",
                    'confidence' => 0.9,
                ]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(100, 50));
            });

        $attackerAgent = $this->makeStructuredCollectionAttackerAgent($llmClient);

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $vulnerabilities);
        self::assertSame('IDOR on user show', $vulnerabilities[0]->title());
    }

    public function test_structured_collection_returns_empty_when_llm_makes_no_tool_calls(): void
    {
        $files = [$this->makeFile('src/Controller/Safe.php')];

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $attackerAgent = $this->makeStructuredCollectionAttackerAgent($llmClient);

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame([], $vulnerabilities);
    }

    public function test_structured_collection_drains_collector_between_chunks_so_findings_are_not_duplicated(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $callIndex = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use (&$callIndex): LLMResponse {
                ++$callIndex;
                $toolRegistry->execute('record_vulnerability', [
                    'type' => 'broken_access_control',
                    'severity' => 'high',
                    'title' => 'finding-'.$callIndex,
                    'description' => 'd',
                    'file_path' => 'src/Controller/A.php',
                    'line_start' => 1,
                    'line_end' => 1,
                    'vulnerable_code' => 'c',
                    'attack_vector' => 'a',
                    'proof' => 'p',
                    'remediation' => 'r',
                    'confidence' => 0.9,
                ]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $attackerPromptBuilder = new AttackerPromptBuilder();
        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: $attackerPromptBuilder,
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                recordVulnerabilityToolFactory: $this->makeRecordToolFactory(),
            ),
            new AttackerScanCollaborators(
                attackerCache: new NullAttackerCache(),
                fileChunker: new FileChunker(ChunkingStrategy::Type, 1),
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: true,
            ),
            new NullLogger(),
        );

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(2, $vulnerabilities);
        self::assertSame(['finding-1', 'finding-2'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
    }

    public function test_structured_collection_stores_drained_findings_in_the_attacker_cache_when_cacheable(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
                $toolRegistry->execute('record_vulnerability', [
                    'type' => 'broken_access_control',
                    'severity' => 'high',
                    'title' => 'cached-finding',
                    'description' => 'd',
                    'file_path' => 'src/Controller/UserController.php',
                    'line_start' => 1,
                    'line_end' => 1,
                    'vulnerable_code' => 'c',
                    'attack_vector' => 'a',
                    'proof' => 'p',
                    'remediation' => 'r',
                    'confidence' => 0.9,
                ]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => 1 === \count($chunk)),
            self::callback(static function (array $payload): bool {
                if (1 !== \count($payload)) {
                    return false;
                }

                $first = $payload[0];

                return \is_array($first) && 'cached-finding' === ($first['title'] ?? null);
            }),
        );

        $attackerAgent = $this->makeStructuredCollectionAttackerAgent($llmClient, $attackerCache);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_structured_collection_skips_cache_store_when_bypass_cache_is_requested(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('completeWithTools')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->expects(self::never())->method('store');

        $attackerAgent = $this->makeStructuredCollectionAttackerAgent($llmClient, $attackerCache);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['bypassCache' => true]);
    }

    public function test_structured_collection_records_chunk_coverage_as_analyzed(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('completeWithTools')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $coverageRecorder = new class implements CoverageRecorderInterface {
            /** @var list<array{stage: string, file: string, status: string}> */
            public array $records = [];

            public function recordCoverage(string $stage, string $filePath, string $status): void
            {
                $this->records[] = ['stage' => $stage, 'file' => $filePath, 'status' => $status];
            }
        };

        $attackerAgent = $this->makeStructuredCollectionAttackerAgent($llmClient);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $coverageRecorder);

        self::assertSame([['stage' => 'attacker', 'file' => 'src/Controller/UserController.php', 'status' => 'analyzed']], $coverageRecorder->records);
    }

    public function test_it_reports_chunk_progress_for_each_chunk(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $recordingProgressReporter = new RecordingProgressReporter();
        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
            ),
            new AttackerScanCollaborators(
                attackerCache: new NullAttackerCache(),
                fileChunker: new FileChunker(ChunkingStrategy::Type, 1),
                progressReporter: $recordingProgressReporter,
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: false,
            ),
            new NullLogger(),
        );

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame(
            [
                ['attacker.chunk.started', ['chunk' => 1, 'total_chunks' => 2]],
                ['attacker.chunk.started', ['chunk' => 2, 'total_chunks' => 2]],
            ],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'attacker.chunk.started' === $event[0],
            )),
        );
    }

    public function test_it_reports_each_recorded_finding_with_severity_type_file_and_line(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(
            LLMResponse::of((string) json_encode([self::recordedFinding('json-path')]), 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $recordingProgressReporter = new RecordingProgressReporter();
        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
            ),
            new AttackerScanCollaborators(
                attackerCache: new NullAttackerCache(),
                fileChunker: new FileChunker(ChunkingStrategy::Type, 1),
                progressReporter: $recordingProgressReporter,
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: false,
            ),
            new NullLogger(),
        );

        $this->callAnalyze($attackerAgent, [$this->makeFile('src/A.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame(
            [['attacker.finding.recorded', ['severity' => 'high', 'type' => 'broken_access_control', 'file' => 'src/A.php', 'line' => 1]]],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'attacker.finding.recorded' === $event[0],
            )),
        );
    }

    public function test_it_reports_each_chunk_completion_with_a_bounded_elapsed_time(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $recordingProgressReporter = new RecordingProgressReporter();
        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
            ),
            new AttackerScanCollaborators(
                attackerCache: new NullAttackerCache(),
                fileChunker: new FileChunker(ChunkingStrategy::Type, 1),
                progressReporter: $recordingProgressReporter,
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: false,
            ),
            new NullLogger(),
        );

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        $completed = array_values(array_filter(
            $recordingProgressReporter->events,
            static fn (array $event): bool => 'attacker.chunk.completed' === $event[0],
        ));

        self::assertSame(
            [[1, 2], [2, 2]],
            array_map(static fn (array $event): array => [$event[1]['chunk'], $event[1]['total_chunks']], $completed),
        );
        self::assertIsFloat($completed[0][1]['elapsed_seconds']);
        self::assertGreaterThanOrEqual(0.0, $completed[0][1]['elapsed_seconds']);
        self::assertLessThan(60.0, $completed[0][1]['elapsed_seconds']);
    }

    private function makeStructuredCollectionAttackerAgent(LLMClientInterface $llmClient, ?AttackerCacheInterface $attackerCache = null): AttackerAgent
    {
        return new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                recordVulnerabilityToolFactory: $this->makeRecordToolFactory(),
            ),
            new AttackerScanCollaborators(
                attackerCache: $attackerCache ?? new NullAttackerCache(),
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: true,
            ),
            new NullLogger(),
        );
    }

    public function test_concurrent_structured_analysis_records_each_chunk_via_its_own_registry_in_order(): void
    {
        $files = [$this->makeFile('src/A.php'), $this->makeFile('src/B.php')];

        $recordingProgressReporter = new RecordingProgressReporter();
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests, int $maxConcurrent, int $maxToolIterations): array {
                self::assertCount(2, $requests);
                self::assertSame(4, $maxConcurrent);
                self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('finding-0a'));
                self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('finding-0b'));
                self::registryOf($requests[1])->execute('record_vulnerability', self::recordedFinding('finding-1'));

                return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
            });

        $auditContext = AuditContext::forProject($this->tmpDir);
        $attackerAgent = $this->makeConcurrentStructuredAgent($llmClient, null, $recordingProgressReporter);

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);

        self::assertSame(
            ['finding-0a', 'finding-0b', 'finding-1'],
            array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities),
        );
        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'file' => 'src/B.php', 'status' => 'analyzed'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(
            [
                ['attacker.chunk.started', ['chunk' => 1, 'total_chunks' => 2]],
                ['attacker.chunk.started', ['chunk' => 2, 'total_chunks' => 2]],
            ],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'attacker.chunk.started' === $event[0],
            )),
        );
        self::assertSame(
            array_fill(0, 3, ['attacker.finding.recorded', ['severity' => 'high', 'type' => 'broken_access_control', 'file' => 'src/A.php', 'line' => 1]]),
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'attacker.finding.recorded' === $event[0],
            )),
        );
        self::assertSame(
            [
                ['attacker.chunk.completed', ['chunk' => 1, 'total_chunks' => 2, 'elapsed_seconds' => 0.0]],
                ['attacker.chunk.completed', ['chunk' => 2, 'total_chunks' => 2, 'elapsed_seconds' => 0.0]],
            ],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'attacker.chunk.completed' === $event[0],
            )),
        );
    }

    public function test_concurrent_structured_analysis_serves_cache_hits_and_dispatches_only_misses(): void
    {
        $files = [$this->makeFile('src/A.php'), $this->makeFile('src/B.php')];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->method('get')->willReturnOnConsecutiveCalls([self::recordedFinding('cached-a')], null);
        $cache->expects(self::once())->method('store');

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests): array {
                self::assertCount(1, $requests);
                self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('fresh-b'));

                return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
            });

        $auditContext = AuditContext::forProject($this->tmpDir);
        $attackerAgent = $this->makeConcurrentStructuredAgent($llmClient, $cache);

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);

        self::assertSame(['cached-a', 'fresh-b'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'cached'],
                ['stage' => 'attacker', 'file' => 'src/B.php', 'status' => 'analyzed'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_concurrent_structured_analysis_rethrows_budget_exceeded(): void
    {
        $files = [$this->makeFile('src/A.php')];

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willThrowException(BudgetExceededException::forTokens(10, 5));

        $auditContext = AuditContext::forProject($this->tmpDir);
        $attackerAgent = $this->makeConcurrentStructuredAgent($llmClient);

        try {
            $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);
            self::fail('expected BudgetExceededException');
        } catch (BudgetExceededException) {
            self::assertSame(
                [['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'aborted']],
                $auditContext->coverage(),
            );
        }
    }

    public function test_concurrent_structured_analysis_rethrows_llm_provider_exception(): void
    {
        $files = [$this->makeFile('src/A.php')];

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willThrowException(new LLMProviderException('platform gone'));

        $auditContext = AuditContext::forProject($this->tmpDir);
        $attackerAgent = $this->makeConcurrentStructuredAgent($llmClient);

        try {
            $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext);
            self::fail('expected LLMProviderException');
        } catch (LLMProviderException) {
            self::assertSame(
                [['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'errored']],
                $auditContext->coverage(),
            );
        }
    }

    public function test_concurrency_is_ignored_when_the_client_cannot_batch_tools(): void
    {
        $files = [$this->makeFile('src/A.php')];

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
                $toolRegistry->execute('record_vulnerability', self::recordedFinding('sequential'));

                return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

        $attackerAgent = $this->makeConcurrentStructuredAgent($llmClient);

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $vulnerabilities);
        self::assertSame('sequential', $vulnerabilities[0]->title());
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        self::assertIsArray($request);
        $toolRegistry = $request['tools'] ?? null;
        self::assertInstanceOf(ToolRegistry::class, $toolRegistry);

        return $toolRegistry;
    }

    public function test_max_concurrent_of_one_stays_sequential_even_on_a_tool_batch_capable_client(): void
    {
        $files = [$this->makeFile('src/A.php')];

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatchWithTools');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
                $toolRegistry->execute('record_vulnerability', self::recordedFinding('sequential'));

                return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                recordVulnerabilityToolFactory: $this->makeRecordToolFactory(),
            ),
            new AttackerScanCollaborators(
                attackerCache: new NullAttackerCache(),
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: true,
                maxConcurrent: 1,
            ),
            new NullLogger(),
        );

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $vulnerabilities);
        self::assertSame('sequential', $vulnerabilities[0]->title());
    }

    public function test_concurrency_is_ignored_when_structured_collection_is_off(): void
    {
        $files = [$this->makeFile('src/A.php')];

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatchWithTools');
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode([self::recordedFinding('json-path')]), 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));

        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                recordVulnerabilityToolFactory: $this->makeRecordToolFactory(),
            ),
            new AttackerScanCollaborators(
                attackerCache: new NullAttackerCache(),
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: false,
                maxConcurrent: 4,
            ),
            new NullLogger(),
        );

        $vulnerabilities = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertCount(1, $vulnerabilities);
        self::assertSame('json-path', $vulnerabilities[0]->title());
    }

    /**
     * @return array<string, mixed>
     */
    private static function recordedFinding(string $title): array
    {
        return [
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => $title,
            'description' => 'desc',
            'file_path' => 'src/A.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.9,
        ];
    }

    private function makeConcurrentStructuredAgent(LLMClientInterface $llmClient, ?AttackerCacheInterface $attackerCache = null, ?ProgressReporterInterface $progressReporter = null): AttackerAgent
    {
        return new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                recordVulnerabilityToolFactory: $this->makeRecordToolFactory(),
            ),
            new AttackerScanCollaborators(
                attackerCache: $attackerCache ?? new NullAttackerCache(),
                fileChunker: new FileChunker(ChunkingStrategy::Type, 1),
                progressReporter: $progressReporter,
            ),
            new AttackerAnalysisSettings(
                useStructuredCollection: true,
                maxConcurrent: 4,
            ),
            new NullLogger(),
        );
    }

    private function makeRecordToolFactory(): RecordVulnerabilityToolFactoryInterface
    {
        return new class implements RecordVulnerabilityToolFactoryInterface {
            public function create(VulnerabilityCollector $vulnerabilityCollector): ToolInterface
            {
                return new RecordVulnerabilityTool($vulnerabilityCollector);
            }
        };
    }

    public function test_context_aware_cache_serves_chunks_carrying_previous_findings(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];
        $previousFindings = [$this->makeVulnerabilityFor('src/Controller/A.php')];

        $cache = $this->createMock(ContextAwareAttackerCacheInterface::class);
        $cache->expects(self::once())
            ->method('getForContext')
            ->with(self::isArray(), self::logicalNot(self::identicalTo('')))
            ->willReturn([]);
        $cache->expects(self::never())->method('get');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $result = $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => $previousFindings]);

        self::assertSame([], $result);
    }

    public function test_context_aware_cache_stores_context_carrying_chunks_after_the_llm_call(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];
        $previousFindings = [$this->makeVulnerabilityFor('src/Controller/A.php')];

        $cache = $this->createMock(ContextAwareAttackerCacheInterface::class);
        $cache->method('getForContext')->willReturn(null);
        $cache->expects(self::once())
            ->method('storeForContext')
            ->with(self::isArray(), self::logicalNot(self::identicalTo('')), []);
        $cache->expects(self::never())->method('store');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => $previousFindings]);
    }

    public function test_context_free_chunks_use_the_empty_context_key_on_a_context_aware_cache(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $cache = $this->createMock(ContextAwareAttackerCacheInterface::class);
        $cache->expects(self::once())->method('getForContext')->with(self::isArray(), '')->willReturn(null);
        $cache->expects(self::once())->method('storeForContext')->with(self::isArray(), '', []);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());
    }

    public function test_context_unaware_cache_is_skipped_for_chunks_carrying_previous_findings(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];
        $previousFindings = [$this->makeVulnerabilityFor('src/Controller/A.php')];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->expects(self::never())->method('get');
        $cache->expects(self::never())->method('store');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => $previousFindings]);
    }

    public function test_context_key_is_the_hash_of_the_rendered_context_preambles(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];
        $vulnerability = $this->makeVulnerabilityFor('src/Controller/A.php');
        $rejectedFinding = $this->makeVulnerabilityFor('src/Controller/A.php');

        $contextKeys = [];
        $cache = self::createStub(ContextAwareAttackerCacheInterface::class);
        $cache->method('getForContext')->willReturnCallback(
            static function (array $chunk, string $contextKey) use (&$contextKeys): ?array {
                $contextKeys[] = $contextKey;

                return null;
            },
        );

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => [$vulnerability], 'rejectedFindings' => [$rejectedFinding]]);

        $attackerContextPromptRenderer = new AttackerContextPromptRenderer();
        $expectedKey = hash(
            'sha256',
            $attackerContextPromptRenderer->renderRejectedFindings([$rejectedFinding])."\0".$attackerContextPromptRenderer->renderPreviousFindings([$vulnerability]),
        );
        self::assertSame([$expectedKey], $contextKeys);
    }

    public function test_previous_and_rejected_findings_produce_distinct_context_keys(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];
        $vulnerability = $this->makeVulnerabilityFor('src/Controller/A.php');

        $contextKeys = [];
        $cache = self::createStub(ContextAwareAttackerCacheInterface::class);
        $cache->method('getForContext')->willReturnCallback(
            static function (array $chunk, string $contextKey) use (&$contextKeys): ?array {
                $contextKeys[] = $contextKey;

                return null;
            },
        );

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $attackerAgent = $this->makeAttackerAgent($llmClient, ['attackerCache' => $cache]);

        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['previousFindings' => [$vulnerability]]);
        $this->callAnalyze($attackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder(), ['rejectedFindings' => [$vulnerability]]);

        self::assertCount(2, $contextKeys);
        self::assertNotSame($contextKeys[0], $contextKeys[1]);
    }

    /**
     * @param array{
     *     attackerCache?: AttackerCacheInterface|null,
     *     logger?: LoggerInterface|null,
     *     toolRegistryFactory?: ToolRegistryFactoryInterface|null,
     *     toolsEnabled?: bool,
     *     maxToolIterations?: int,
     *     staticPreScanner?: StaticPreScannerInterface|null,
     *     leanMode?: bool,
     * } $overrides
     */
    private function makeAttackerAgent(LLMClientInterface $llmClient, array $overrides = []): AttackerAgent
    {
        return new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
            ),
            new AttackerScanCollaborators(
                attackerCache: $overrides['attackerCache'] ?? new NullAttackerCache(),
                staticPreScanner: $overrides['staticPreScanner'] ?? null,
                toolRegistryFactory: $overrides['toolRegistryFactory'] ?? null,
            ),
            new AttackerAnalysisSettings(
                toolsEnabled: $overrides['toolsEnabled'] ?? AttackerAgent::DEFAULT_TOOLS_ENABLED,
                maxToolIterations: $overrides['maxToolIterations'] ?? AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS,
                leanMode: $overrides['leanMode'] ?? AttackerAgent::DEFAULT_LEAN_MODE,
            ),
            $overrides['logger'] ?? new NullLogger(),
        );
    }
}
