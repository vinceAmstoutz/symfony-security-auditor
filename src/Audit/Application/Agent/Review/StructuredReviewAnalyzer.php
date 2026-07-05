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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;

/**
 * Reviews findings one at a time, collecting each verdict through a
 * schema-enforced `record_review` tool call. Cache hits short-circuit the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StructuredReviewAnalyzer
{
    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private RecordReviewToolFactoryInterface $recordReviewToolFactory,
        private LoggerInterface $logger,
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
    public function analyze(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): array
    {
        $reviewed = [];
        foreach ($vulnerabilities as $vulnerability) {
            $reviewed[] = $this->reviewSingle($vulnerability, $projectFiles, $coverageRecorder, $bypassCache);
        }

        return $reviewed;
    }

    /**
     * @param list<ProjectFile> $projectFiles
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function reviewSingle(Vulnerability $vulnerability, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): Vulnerability
    {
        $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);

        $cached = $this->reviewerVerdictCache->get($vulnerability, $codeContext, $bypassCache);
        if (null !== $cached) {
            return $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $cached, $coverageRecorder);
        }

        $systemPrompt = $this->reviewerPromptBuilder->buildSystemPrompt();
        $userMessage = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext);

        $session = StructuredReviewCollectionSession::begin($this->recordReviewToolFactory, $this->logger);

        try {
            $this->llmClient->completeWithTools($systemPrompt, $userMessage, $session->toolRegistry, $this->maxToolIterations);

            $verdict = $session->drain()[0] ?? null;
            if (!$bypassCache) {
                $this->reviewerVerdictCache->store($vulnerability, $codeContext, $verdict);
            }

            return $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $verdict, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->reviewOutcomeRecorder->recordReviewError($vulnerability, $exception, $coverageRecorder);
        }
    }
}
