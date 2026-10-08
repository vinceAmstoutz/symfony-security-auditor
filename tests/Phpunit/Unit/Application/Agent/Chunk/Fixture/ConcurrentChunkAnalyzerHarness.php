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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture;

use PHPUnit\Framework\Assert;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextKeyDeriver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ConcurrentChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ConcurrentChunkAnalyzerHarness
{
    public static function analyzer(ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient, int $maxConcurrent, ?AttackerCacheInterface $attackerCache = null, ?LoggerInterface $logger = null, ?ProgressReporterInterface $progressReporter = null): ConcurrentChunkAnalyzer
    {
        return new ConcurrentChunkAnalyzer(
            $toolBatchCapableLLMClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver()),
            new AttackerChunkCache($attackerCache ?? new NullAttackerCache(), ChunkAnalysisInputs::vulnerabilityFactory(), new NullLogger()),
            ChunkAnalysisInputs::vulnerabilityFactory(),
            $logger ?? new NullLogger(),
            $progressReporter ?? new NullProgressReporter(),
            3,
            new RecordVulnerabilityToolFactory(),
            $maxConcurrent,
        );
    }

    public static function analyzerRecordingThrough(ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient, int $maxConcurrent, RecordVulnerabilityToolFactoryInterface $recordVulnerabilityToolFactory, ?AttackerCacheInterface $attackerCache = null, ?LoggerInterface $logger = null): ConcurrentChunkAnalyzer
    {
        return new ConcurrentChunkAnalyzer(
            $toolBatchCapableLLMClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver()),
            new AttackerChunkCache($attackerCache ?? new NullAttackerCache(), ChunkAnalysisInputs::vulnerabilityFactory(), new NullLogger()),
            ChunkAnalysisInputs::vulnerabilityFactory(),
            $logger ?? new NullLogger(),
            new NullProgressReporter(),
            3,
            $recordVulnerabilityToolFactory,
            $maxConcurrent,
        );
    }

    public static function analyzerBuildingPromptsWith(ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient, int $maxConcurrent, AttackerPromptBuilderInterface $attackerPromptBuilder): ConcurrentChunkAnalyzer
    {
        return new ConcurrentChunkAnalyzer(
            $toolBatchCapableLLMClient,
            new ChunkContextFactory($attackerPromptBuilder, new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver()),
            new AttackerChunkCache(new NullAttackerCache(), ChunkAnalysisInputs::vulnerabilityFactory(), new NullLogger()),
            ChunkAnalysisInputs::vulnerabilityFactory(),
            new NullLogger(),
            new NullProgressReporter(),
            3,
            new RecordVulnerabilityToolFactory(),
            $maxConcurrent,
        );
    }

    public static function registryOf(mixed $request): ToolRegistry
    {
        Assert::assertIsArray($request);
        $toolRegistry = $request['tools'] ?? null;
        Assert::assertInstanceOf(ToolRegistry::class, $toolRegistry);

        return $toolRegistry;
    }

    /**
     * @return array<string, mixed>
     */
    public static function recordedFinding(string $title): array
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

    /**
     * @return array<string, int> coverage status => count, sorted by status
     */
    public static function statusCounts(RecordingCoverageRecorder $recordingCoverageRecorder): array
    {
        $counts = array_count_values(array_column($recordingCoverageRecorder->coverage, 'status'));
        ksort($counts);

        return $counts;
    }
}
