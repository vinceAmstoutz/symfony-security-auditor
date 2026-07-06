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

use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Reviews findings one at a time via the JSON response path, optionally with
 * the investigation tool registry. Cache hits short-circuit the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SequentialReviewAnalyzer
{
    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private int $maxToolIterations,
    ) {}

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function analyze(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, bool $bypassCache): array
    {
        $reviewed = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            try {
                $reviewed[] = $this->reviewSingle($vulnerability, $projectFiles, $coverageRecorder, $toolRegistry, $bypassCache);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemaining($vulnerabilities, $index + 1, 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemaining($vulnerabilities, $index + 1, 'errored', $coverageRecorder);

                throw $llmProviderException;
            }
        }

        return $reviewed;
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     */
    private function failRemaining(array $vulnerabilities, int $fromIndex, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($vulnerabilities as $index => $vulnerability) {
            if ($index < $fromIndex) {
                continue;
            }

            $this->reviewOutcomeRecorder->recordUnreached($vulnerability, $status, $coverageRecorder);
        }
    }

    /**
     * @param list<ProjectFile> $projectFiles
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function reviewSingle(Vulnerability $vulnerability, array $projectFiles, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, bool $bypassCache): Vulnerability
    {
        $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);

        $cached = $this->reviewerVerdictCache->get($vulnerability, $codeContext, $bypassCache);
        if (null !== $cached) {
            return $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $cached, $coverageRecorder);
        }

        $systemPrompt = $this->reviewerPromptBuilder->buildSystemPrompt();
        $userMessage = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext);

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            return $this->reviewOutcomeRecorder->applyResponse($vulnerability, $response, $coverageRecorder, $bypassCache ? null : $codeContext);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->reviewOutcomeRecorder->recordUnreached($vulnerability, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->reviewOutcomeRecorder->recordUnreached($vulnerability, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->reviewOutcomeRecorder->recordReviewError($vulnerability, $exception, $coverageRecorder);
        }
    }
}
