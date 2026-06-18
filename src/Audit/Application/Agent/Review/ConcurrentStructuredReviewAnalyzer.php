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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Resolves every single-finding review in concurrency windows via the
 * tool-batch-capable client, each verdict arriving through its own
 * schema-enforced `record_review` tool. Cached verdicts are served first;
 * only the misses are dispatched.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConcurrentStructuredReviewAnalyzer
{
    public function __construct(
        private ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private RecordReviewToolFactoryInterface $recordReviewToolFactory,
        private LoggerInterface $logger,
        private int $maxConcurrent,
        private int $maxToolIterations,
    ) {}

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    public function analyze(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): array
    {
        $reviewed = [];
        $codeContexts = [];
        $reviewCollectors = [];
        $pendingIndexes = [];
        $requests = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);
            $codeContexts[$index] = $codeContext;

            $cached = $this->reviewerVerdictCache->get($vulnerability, $codeContext, $bypassCache);
            if (null !== $cached) {
                $reviewed[$index] = $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $cached, $coverageRecorder);

                continue;
            }

            $reviewCollector = new ReviewCollector();
            $reviewCollectors[$index] = $reviewCollector;
            $pendingIndexes[] = $index;
            $requests[] = $this->buildRequest($vulnerability, $codeContext, $reviewCollector);
        }

        if ([] !== $requests) {
            $batch = new ConcurrentReviewBatch($requests, $pendingIndexes, $reviewCollectors, $vulnerabilities, $codeContexts);
            $this->dispatchPending($batch, $coverageRecorder, $bypassCache, $reviewed);
        }

        ksort($reviewed);

        return array_values($reviewed);
    }

    /**
     * @return array{system: string, user: string, tools: ToolRegistry}
     */
    private function buildRequest(Vulnerability $vulnerability, string $codeContext, ReviewCollector $reviewCollector): array
    {
        return [
            'system' => $this->reviewerPromptBuilder->buildSystemPrompt(),
            'user' => $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext),
            'tools' => new ToolRegistry([$this->recordReviewToolFactory->create($reviewCollector)], $this->logger),
        ];
    }

    /**
     * @param array<int, Vulnerability> $reviewed
     *
     * @param-out array<int, Vulnerability> $reviewed
     */
    private function dispatchPending(ConcurrentReviewBatch $batch, CoverageRecorderInterface $coverageRecorder, bool $bypassCache, array &$reviewed): void
    {
        try {
            $this->toolBatchCapableLLMClient->completeBatchWithTools($batch->requests, $this->maxConcurrent, $this->maxToolIterations);

            foreach ($batch->pendingIndexes as $index) {
                $reviewed[$index] = $this->recordPendingVerdict($index, $batch, $coverageRecorder, $bypassCache);
            }
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            $this->recordPendingErrors($batch->pendingIndexes, $batch->vulnerabilities, $exception, $coverageRecorder, $reviewed);
        }
    }

    private function recordPendingVerdict(int $index, ConcurrentReviewBatch $batch, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): Vulnerability
    {
        $verdict = $batch->reviewCollectors[$index]->drain()[0] ?? null;
        if (!$bypassCache) {
            $this->reviewerVerdictCache->store($batch->vulnerabilities[$index], $batch->codeContexts[$index], $verdict);
        }

        return $this->reviewOutcomeRecorder->recordVerdict($batch->vulnerabilities[$index], $verdict, $coverageRecorder);
    }

    /**
     * @param list<int>                 $pendingIndexes
     * @param list<Vulnerability>       $vulnerabilities
     * @param array<int, Vulnerability> $reviewed
     */
    private function recordPendingErrors(array $pendingIndexes, array $vulnerabilities, Throwable $exception, CoverageRecorderInterface $coverageRecorder, array &$reviewed): void
    {
        foreach ($pendingIndexes as $pendingIndex) {
            $reviewed[$pendingIndex] = $this->reviewOutcomeRecorder->recordReviewError($vulnerabilities[$pendingIndex], $exception, $coverageRecorder);
        }
    }
}
