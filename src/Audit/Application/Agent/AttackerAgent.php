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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use JsonException;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AttackerAgent implements AttackerAgentInterface
{
    private const int CHUNK_SIZE = 10;

    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public const int DEFAULT_MAX_TOOL_ITERATIONS = 8;

    public const bool DEFAULT_TOOLS_ENABLED = false;

    public function __construct(
        private LLMClientInterface $llmClient,
        private AttackerPromptBuilderInterface $attackerPromptBuilder,
        private VulnerabilityFactory $vulnerabilityFactory,
        private AttackerCacheInterface $attackerCache,
        private LoggerInterface $logger,
        private ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
        private bool $toolsEnabled = self::DEFAULT_TOOLS_ENABLED,
        private int $maxToolIterations = self::DEFAULT_MAX_TOOL_ITERATIONS,
    ) {}

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<Vulnerability>
     */
    public function analyze(array $files, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false): array
    {
        if ([] === $files) {
            return [];
        }

        $useTools = $this->toolsEnabled && $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;

        $this->logger->info('Attacker agent starting analysis', [
            'files' => \count($files),
            'tools_enabled' => $useTools,
            'cache_bypassed' => $bypassCache,
        ]);

        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($files) : null;

        $chunks = $this->chunkFiles($files);
        $allVulnerabilities = [];

        foreach ($chunks as $index => $chunk) {
            $this->logger->debug(\sprintf('Analyzing chunk %d/%d', $index + 1, \count($chunks)));

            $vulnerabilities = $this->analyzeChunk($chunk, $symfonyMapping, $coverageRecorder, $toolRegistry, $bypassCache);
            $allVulnerabilities = [...$allVulnerabilities, ...$vulnerabilities];

            $this->logger->debug('Chunk analysis complete', [
                'chunk' => $index + 1,
                'found' => \count($vulnerabilities),
                'total_so_far' => \count($allVulnerabilities),
            ]);
        }

        $this->logger->info('Attacker agent complete', [
            'total_vulnerabilities' => \count($allVulnerabilities),
        ]);

        return $allVulnerabilities;
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @return list<Vulnerability>
     */
    private function analyzeChunk(array $chunk, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, bool $bypassCache): array
    {
        if (!$bypassCache) {
            $cached = $this->attackerCache->get($chunk);

            if (null !== $cached) {
                $this->logger->info('Attacker chunk served from cache', ['files' => \count($chunk)]);
                $this->recordChunkCoverage($chunk, 'cached', $coverageRecorder);

                return $this->vulnerabilityFactory->fromList(array_values($cached));
            }
        }

        $systemPrompt = $this->attackerPromptBuilder->buildSystemPrompt($chunk);
        $userMessage = $this->attackerPromptBuilder->buildUserMessage($chunk, $symfonyMapping);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            if ($response->isEmpty()) {
                $this->recordChunkCoverage($chunk, 'analyzed', $coverageRecorder);

                return [];
            }

            /** @var list<mixed> $rawData */
            $rawData = $response->parseJson();

            if (!$bypassCache) {
                /** @var list<array<string, mixed>> $cacheablePayload */
                $cacheablePayload = array_values(array_filter($rawData, 'is_array'));
                $this->attackerCache->store($chunk, $cacheablePayload);
            }

            $this->recordChunkCoverage($chunk, 'analyzed', $coverageRecorder);

            return $this->vulnerabilityFactory->fromList($rawData);
        } catch (BudgetExceededException $budgetExceededException) {
            // Budget exhaustion is a deliberate abort, not an LLM failure;
            // let it bubble up so RunAuditUseCase can wrap it with a partial report.
            $this->recordChunkCoverage($chunk, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->recordChunkCoverage($chunk, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (JsonException $exception) {
            $this->logger->error('Failed to parse attacker agent JSON response', [
                'error' => $exception->getMessage(),
                'content_preview' => substr($response->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);
            $this->recordChunkCoverage($chunk, 'errored', $coverageRecorder);

            return [];
        } catch (Throwable $exception) {
            $this->logger->error('Attacker agent LLM call failed', [
                'error' => $exception->getMessage(),
            ]);
            $this->recordChunkCoverage($chunk, 'errored', $coverageRecorder);

            return [];
        }
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function recordChunkCoverage(array $chunk, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($chunk as $file) {
            $coverageRecorder->recordCoverage(AgentRole::Attacker->value, $file->relativePath(), $status);
        }
    }

    /**
     * Sorts files by security relevance (controllers first) then chunks them.
     *
     * @param list<ProjectFile> $files
     *
     * @return list<list<ProjectFile>>
     */
    private function chunkFiles(array $files): array
    {
        $order = ['controller', 'voter', 'entity', 'repository', 'form'];
        usort($files, static function (ProjectFile $a, ProjectFile $b) use ($order): int {
            $priority = static function (ProjectFile $projectFile) use ($order): int {
                $idx = array_search($projectFile->type(), $order, true);

                return false !== $idx ? $idx : \count($order);
            };

            return $priority($a) <=> $priority($b);
        });

        /* @var list<list<ProjectFile>> $chunks */
        return array_chunk($files, self::CHUNK_SIZE);
    }
}
