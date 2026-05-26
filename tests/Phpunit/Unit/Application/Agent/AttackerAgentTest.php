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

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;

#[AllowMockObjectsWithoutExpectations]
final class AttackerAgentTest extends TestCase
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    private string $tmpDir;

    public function test_it_returns_empty_array_when_no_files(): void
    {
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $symfonyMapping = SymfonyMapping::create();
        $result = $attackerAgent->analyze([], $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_calls_llm_with_files_and_returns_vulnerabilities(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::create(controllers: $files);

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

        $llmResponse = LLMResponse::create($llmPayload, 100, 200, 'claude', 'end_turn');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $vulnerabilities = $attackerAgent->analyze($files, $symfonyMapping, new NullCoverageRecorder());

        self::assertCount(1, $vulnerabilities);
        self::assertSame('Missing access control', $vulnerabilities[0]->title());
    }

    public function test_it_handles_llm_json_parse_error_gracefully(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::create();

        $llmResponse = LLMResponse::create('not valid json {{{', 100, 10, 'claude', 'end_turn');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $attackerAgent->analyze($files, $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_handles_llm_exception_gracefully(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::create();

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willThrowException(new RuntimeException('API timeout'));

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $attackerAgent->analyze($files, $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_handles_empty_llm_response(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        $symfonyMapping = SymfonyMapping::create();

        $llmResponse = LLMResponse::create('', 100, 0, 'claude', 'end_turn');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $attackerAgent->analyze($files, $symfonyMapping, new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_chunks_files_for_large_projects(): void
    {
        // Create 15 files (> CHUNK_SIZE of 10)
        $files = [];
        for ($i = 1; $i <= 15; ++$i) {
            $files[] = $this->makeFile(\sprintf('src/Service/Service%d.php', $i));
        }

        $symfonyMapping = SymfonyMapping::create();
        $llmResponse = LLMResponse::create('[]', 100, 10, 'claude', 'end_turn');

        $llmClient = $this->createMock(LLMClientInterface::class);
        // Should be called twice (ceil(15/10) = 2 chunks)
        $llmClient
            ->expects(self::exactly(2))
            ->method('complete')
            ->willReturn($llmResponse);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $attackerAgent->analyze($files, $symfonyMapping, new NullCoverageRecorder());
    }

    public function test_it_accumulates_vulnerabilities_from_multiple_chunks(): void
    {
        $files = [];
        for ($i = 1; $i <= 12; ++$i) {
            $files[] = $this->makeFile(\sprintf('src/Service/Service%d.php', $i));
        }

        $symfonyMapping = SymfonyMapping::create();

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
                LLMResponse::create($chunk1Json, 100, 100, 'claude', 'end_turn'),
                LLMResponse::create($chunk2Json, 100, 100, 'claude', 'end_turn'),
            );

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $result = $attackerAgent->analyze($files, $symfonyMapping, new NullCoverageRecorder());

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

                return LLMResponse::create('[]', 100, 10, 'claude', 'end_turn');
            });

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $attackerAgent->analyze(
            [$this->makeFile($lowerPriorityPath), $this->makeFile($higherPriorityPath)],
            SymfonyMapping::create(),
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
        yield 'controllers before services' => ['src/Controller/SomeController.php', 'src/Service/SomeService.php'];
        yield 'controllers before voters' => ['src/Controller/SomeController.php', 'src/Security/UserVoter.php'];
        yield 'voters before entities' => ['src/Security/UserVoter.php', 'src/Entity/User.php'];
        yield 'entities before repositories' => ['src/Entity/Product.php', 'src/Repository/UserRepository.php'];
        yield 'repositories before forms' => ['src/Repository/OrderRepository.php', 'src/Form/UserType.php'];
        yield 'forms before services' => ['src/Form/ProductType.php', 'src/Service/OtherService.php'];
    }

    public function test_it_does_not_call_llm_when_no_files_and_returns_empty(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('info');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $result = $attackerAgent->analyze([], SymfonyMapping::create(), new NullCoverageRecorder());

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
            ->willReturn(LLMResponse::create('[]', 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

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
            ->willReturn(LLMResponse::create('invalid json {{{', 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $result = $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

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
            ->willReturn(LLMResponse::create($longInvalidContent, 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $attackerAgent->analyze(
            [$this->makeFile('src/Controller/UserController.php')],
            SymfonyMapping::create(),
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

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $result = $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

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
            ->willReturn(LLMResponse::create('[]', 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

        self::assertSame(['Attacker agent starting analysis', ['files' => 2, 'tools_enabled' => false, 'cache_bypassed' => false]], $infoLogs[0]);
        self::assertSame(['Attacker agent complete', ['total_vulnerabilities' => 0]], $infoLogs[1]);
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
            ->willReturn(LLMResponse::create('[]', 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

        self::assertCount(2, $debugLogs);
        self::assertSame('Analyzing chunk 1/1', $debugLogs[0][0]);
        self::assertSame('Chunk analysis complete', $debugLogs[1][0]);
        self::assertSame(['chunk' => 1, 'found' => 0, 'total_so_far' => 0], $debugLogs[1][1]);
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
            ->willReturn(LLMResponse::create('[]', 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

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
            ->willReturn(LLMResponse::create('', 10, 0, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger);

        $result = $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

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

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $result = $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

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
            ->willReturn(LLMResponse::create((string) json_encode($rawPayload), 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
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
            ->willReturn(LLMResponse::create((string) json_encode($mixedPayload), 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
    }

    public function test_it_does_not_store_in_cache_when_llm_returns_empty_response(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $cache = $this->createMock(AttackerCacheInterface::class);
        $cache->method('get')->willReturn(null);
        $cache->expects(self::never())->method('store');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::create('', 10, 0, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
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
            ->willReturn(LLMResponse::create('[]', 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder(), true);
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
            ->willReturn(LLMResponse::create((string) json_encode($rawPayload), 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $result = $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder(), true);

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
            ->willReturn(LLMResponse::create('[]', 10, 10, 'claude', 'end_turn'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);

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

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);

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

        $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);

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
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(BudgetExceededException::forCost(2.0, 1.0));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        try {
            $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);
            self::fail('Expected BudgetExceededException to propagate');
        } catch (BudgetExceededException) {
            // expected — the agent rethrows; coverage should still be recorded.
        }

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'aborted'],
                ['stage' => 'attacker', 'file' => 'src/Controller/B.php', 'status' => 'aborted'],
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
            ->willReturn(LLMResponse::create('', 10, 0, 'claude', 'end_turn'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);

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
            ->willReturn(LLMResponse::create('garbage {{{', 10, 10, 'claude', 'end_turn'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);

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
            ->willReturn(LLMResponse::create('[]', 0, 0, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, null, $factory, true);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
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
            ->willReturn(LLMResponse::create('[]', 0, 0, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, null, $factory, false);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
    }

    public function test_it_uses_non_tool_path_when_factory_is_null_even_if_enabled(): void
    {
        $files = [$this->makeFile('src/Controller/A.php')];

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::create('[]', 0, 0, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, null, null, true);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
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
            ->willReturn(LLMResponse::create('[]', 0, 0, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, null, $factory, true, 13);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
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
            ->willReturn(LLMResponse::create('[]', 0, 0, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, null, $logger, $factory, true);

        $attackerAgent->analyze([$this->makeFile('src/A.php')], SymfonyMapping::create(), new NullCoverageRecorder());

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

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache, $logger);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

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
            ->willReturn(LLMResponse::create('garbage {{{', 10, 10, 'claude', 'end_turn'));

        $attackerAgent = $this->makeAttackerAgent($llmClient, $cache);

        $attackerAgent->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());
    }

    public function test_it_propagates_llm_provider_exception_and_records_errored_coverage(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new LLMProviderException('No provider found for model "claude-opus-4-7".'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        try {
            $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);
            self::fail('Expected LLMProviderException to propagate');
        } catch (LLMProviderException) {
            // expected — the agent rethrows; coverage must still be recorded.
        }

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'file' => 'src/Controller/B.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_it_propagates_exhausted_transient_failure_and_records_errored_coverage(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
        ];

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(
                TransientLLMFailureException::afterExhaustedAttempts(3, new RuntimeException('Rate limit exceeded')),
            );

        $auditContext = AuditContext::forProject($this->tmpDir);

        $attackerAgent = $this->makeAttackerAgent($llmClient);

        try {
            $attackerAgent->analyze($files, SymfonyMapping::create(), $auditContext);
            self::fail('Expected LLMProviderException to propagate');
        } catch (LLMProviderException) {
            // TransientLLMFailureException extends LLMProviderException — expected.
        }

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'file' => 'src/Controller/B.php', 'status' => 'errored'],
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

    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php class Foo {}');
    }

    private function makeAttackerAgent(
        LLMClientInterface $llmClient,
        ?AttackerCacheInterface $attackerCache = null,
        ?LoggerInterface $logger = null,
        ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
        bool $toolsEnabled = AttackerAgent::DEFAULT_TOOLS_ENABLED,
        int $maxToolIterations = AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS,
    ): AttackerAgent {
        return new AttackerAgent(
            llmClient: $llmClient,
            attackerPromptBuilder: new AttackerPromptBuilder(),
            vulnerabilityFactory: new VulnerabilityFactory(new NullLogger()),
            attackerCache: $attackerCache ?? new NullAttackerCache(),
            logger: $logger ?? new NullLogger(),
            toolRegistryFactory: $toolRegistryFactory,
            toolsEnabled: $toolsEnabled,
            maxToolIterations: $maxToolIterations,
        );
    }
}
