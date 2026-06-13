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

use JsonException;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Reviews findings in batches of `batchSize`: one LLM call per batch, verdicts
 * matched back to findings by id. The structured mode collects verdicts
 * through a `record_review` tool; the JSON mode parses the model's array
 * response, optionally with the investigation tool registry.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BatchReviewAnalyzer
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private BatchVerdictApplier $batchVerdictApplier,
        private LoggerInterface $logger,
        private int $maxToolIterations,
        private ?RecordReviewToolFactoryInterface $recordReviewToolFactory,
    ) {}

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     * @param int<1, max>         $batchSize
     *
     * @return list<Vulnerability>
     */
    public function analyze(array $vulnerabilities, array $projectFiles, int $batchSize, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, bool $structured): array
    {
        $reviewed = [];
        foreach (array_chunk($vulnerabilities, $batchSize) as $batch) {
            $reviewed = [
                ...$reviewed,
                ...$structured
                    ? $this->reviewBatchViaStructuredCollection($batch, $projectFiles, $coverageRecorder)
                    : $this->reviewBatch($batch, $projectFiles, $coverageRecorder, $toolRegistry),
            ];
        }

        return $reviewed;
    }

    /**
     * @param list<Vulnerability> $batch
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    private function reviewBatch(array $batch, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): array
    {
        [$systemPrompt, $userMessage] = $this->buildBatchPrompts($batch, $projectFiles);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            if ($response->isEmpty()) {
                return $this->batchVerdictApplier->rejectBatch($batch, $coverageRecorder);
            }

            /** @var array<int|string, mixed> $rawData */
            $rawData = $response->parseJson();

            return $this->batchVerdictApplier->applyBatchReview($batch, $rawData, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (JsonException $exception) {
            $this->logger->error('Failed to parse reviewer batch response', [
                'batch_size' => \count($batch),
                'error' => $exception->getMessage(),
                'content_preview' => substr($response->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);

            return $this->batchVerdictApplier->markBatchErrored($batch, $coverageRecorder);
        } catch (Throwable $exception) {
            return $this->batchVerdictApplier->recordBatchError($batch, $exception, $coverageRecorder);
        }
    }

    /**
     * @param list<Vulnerability> $batch
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    private function reviewBatchViaStructuredCollection(array $batch, array $projectFiles, CoverageRecorderInterface $coverageRecorder): array
    {
        \assert($this->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface);

        [$systemPrompt, $userMessage] = $this->buildBatchPrompts($batch, $projectFiles);

        $reviewCollector = new ReviewCollector();
        $toolRegistry = new ToolRegistry([$this->recordReviewToolFactory->create($reviewCollector)], $this->logger);

        try {
            $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations);

            return $this->batchVerdictApplier->applyBatchReview($batch, $reviewCollector->drain(), $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->batchVerdictApplier->recordBatchError($batch, $exception, $coverageRecorder);
        }
    }

    /**
     * @param list<Vulnerability> $batch
     * @param list<ProjectFile>   $projectFiles
     *
     * @return array{0: string, 1: string}
     */
    private function buildBatchPrompts(array $batch, array $projectFiles): array
    {
        $codeContexts = [];
        foreach ($batch as $vulnerability) {
            $codeContexts[$vulnerability->id()] = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);
        }

        return [
            $this->reviewerPromptBuilder->buildBatchSystemPrompt(),
            $this->reviewerPromptBuilder->buildBatchUserMessage($batch, $codeContexts),
        ];
    }
}
