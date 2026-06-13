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
            $requests[] = [
                'system' => $this->reviewerPromptBuilder->buildSystemPrompt(),
                'user' => $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext),
                'tools' => new ToolRegistry([$this->recordReviewToolFactory->create($reviewCollector)], $this->logger),
            ];
        }

        if ([] !== $requests) {
            try {
                $this->toolBatchCapableLLMClient->completeBatchWithTools($requests, $this->maxConcurrent, $this->maxToolIterations);

                foreach ($pendingIndexes as $index) {
                    $verdict = $reviewCollectors[$index]->drain()[0] ?? null;
                    if (!$bypassCache) {
                        $this->reviewerVerdictCache->store($vulnerabilities[$index], $codeContexts[$index], $verdict);
                    }

                    $reviewed[$index] = $this->reviewOutcomeRecorder->recordVerdict($vulnerabilities[$index], $verdict, $coverageRecorder);
                }
            } catch (BudgetExceededException $budgetExceededException) {
                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                throw $llmProviderException;
            } catch (Throwable $exception) {
                foreach ($pendingIndexes as $pendingIndex) {
                    $reviewed[$pendingIndex] = $this->reviewOutcomeRecorder->recordReviewError($vulnerabilities[$pendingIndex], $exception, $coverageRecorder);
                }
            }
        }

        ksort($reviewed);

        return array_values($reviewed);
    }
}
