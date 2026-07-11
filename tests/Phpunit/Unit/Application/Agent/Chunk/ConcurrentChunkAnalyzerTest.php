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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ConcurrentChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ConcurrentChunkAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_it_records_a_cached_chunks_findings_as_found_vulnerabilities(): void
    {
        $cache = self::createStub(AttackerCacheInterface::class);
        $cache->method('get')->willReturn([self::recordedFinding('cached-finding')]);

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);

        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 4, $cache);

        $concurrentChunkAnalyzer->analyze([[$this->makeFile('src/A.php')]], $this->request(), $recordingCoverageRecorder, new RiskMarkerIndex([]), null);

        self::assertSame(['cached-finding'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $recordingCoverageRecorder->found));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_max_concurrent_of_one_dispatches_each_pending_chunk_in_its_own_window(): void
    {
        $requestCounts = [];
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$requestCounts): array {
                $requestCounts[] = \count($requests);
                foreach ($requests as $request) {
                    self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('finding'));
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 1);

        $concurrentChunkAnalyzer->analyze(
            [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            new RiskMarkerIndex([]),
            null,
        );

        self::assertSame([1, 1], $requestCounts);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_generic_failure_in_a_later_window_preserves_every_earlier_windows_result(): void
    {
        $callCount = 0;
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$callCount): array {
                ++$callCount;
                if (2 === $callCount) {
                    throw new RuntimeException('second window tore');
                }

                foreach ($requests as $request) {
                    self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('first-window'));
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 2);

        [$vulnerabilities] = $concurrentChunkAnalyzer->analyze(
            [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')], [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            new RiskMarkerIndex([]),
            null,
        );

        self::assertCount(2, $vulnerabilities);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finalize_failure_logs_a_warning_carrying_the_underlying_error(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests): array {
                self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('finding'));

                return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
            });

        $throwingCoverageRecorder = new class implements CoverageRecorderInterface {
            #[Override]
            public function recordCoverage(string $stage, string $filePath, string $status): void
            {
                if ('analyzed' === $status) {
                    throw new RuntimeException('coverage sink unavailable');
                }
            }

            #[Override]
            public function recordReviewedFinding(Vulnerability $vulnerability): void {}

            #[Override]
            public function drainReviewedFindings(): array
            {
                return [];
            }

            #[Override]
            public function recordFoundVulnerability(Vulnerability $vulnerability): void {}

            #[Override]
            public function drainFoundVulnerabilities(): array
            {
                return [];
            }
        };

        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 4, null, $logger);

        $concurrentChunkAnalyzer->analyze([[$this->makeFile('src/A.php')]], $this->request(), $throwingCoverageRecorder, new RiskMarkerIndex([]), null);

        self::assertContains(
            ['Finalizing an attacker chunk result failed; the chunk is recorded as errored and its siblings in the same window are preserved.', ['error' => 'coverage sink unavailable']],
            $warnings,
        );
    }

    private function makeAnalyzer(ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient, int $maxConcurrent, ?AttackerCacheInterface $attackerCache = null, ?LoggerInterface $logger = null): ConcurrentChunkAnalyzer
    {
        return new ConcurrentChunkAnalyzer(
            $toolBatchCapableLLMClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer()),
            new AttackerChunkCache($attackerCache ?? new NullAttackerCache(), $this->vulnerabilityFactory(), new NullLogger()),
            $this->vulnerabilityFactory(),
            $logger ?? new NullLogger(),
            new NullProgressReporter(),
            3,
            new RecordVulnerabilityToolFactory(),
            $maxConcurrent,
        );
    }

    private function vulnerabilityFactory(): VulnerabilityFactory
    {
        return new VulnerabilityFactory(new NullLogger(), Validation::createValidator());
    }

    private function request(): AttackerAnalysisRequest
    {
        return new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        self::assertIsArray($request);
        $toolRegistry = $request['tools'] ?? null;
        self::assertInstanceOf(ToolRegistry::class, $toolRegistry);

        return $toolRegistry;
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
}
