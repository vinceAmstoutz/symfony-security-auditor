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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic;

use Override;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordingToolReach;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CoverageCriticPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Asks the model, from a summary of the audit and no source code, which entry
 * points or sibling paths no attacker chunk showed together, and returns each
 * gap it names on the audited files as a {@see CoverageGap}.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CoverageCritic implements CoverageCriticInterface
{
    public function __construct(
        private LLMClientInterface $llmClient,
        private CoverageCriticPromptBuilderInterface $coverageCriticPromptBuilder,
        private RecordCoverageGapToolFactoryInterface $recordCoverageGapToolFactory,
        private FileChunker $fileChunker,
        private LoggerInterface $logger,
        private CoverageCriticSettings $coverageCriticSettings,
    ) {}

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[Override]
    public function gaps(SymfonyMapping $symfonyMapping, AuditContext $auditContext): array
    {
        $files = $auditContext->projectFiles();
        if ([] === $files) {
            return [];
        }

        $systemPrompt = $this->coverageCriticPromptBuilder->buildSystemPrompt($this->coverageCriticSettings->maxGaps, $this->coverageCriticSettings->structuredCollection);
        $userMessage = $this->coverageCriticPromptBuilder->buildUserMessage($symfonyMapping, $this->fileChunker->chunk($files), $auditContext);

        try {
            $payloads = $this->coverageCriticSettings->structuredCollection
                ? $this->recordedGaps($systemPrompt, $userMessage)
                : $this->answeredGaps($this->llmClient->complete($systemPrompt, $userMessage));
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->noGapAfter($llmRequestTooLargeException);
        } catch (BudgetExceededException|LLMProviderException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            return $this->noGapAfter($throwable);
        }

        return CoverageGapFactory::fromPayloads($payloads, $files, $this->coverageCriticSettings->maxGaps);
    }

    /**
     * The critic only adds work to a finished loop, so a failure that does not
     * stop every call — an answer it cannot read, a summary the model cannot
     * fit — costs its gaps, never the run.
     *
     * @return list<CoverageGap>
     */
    private function noGapAfter(Throwable $throwable): array
    {
        $this->logger->warning('The coverage critic failed, so no gap is analyzed', ['error' => $throwable->getMessage()]);

        return [];
    }

    /**
     * The gaps the model recorded, or those its answer lists when the client
     * never offered the recording tool to the model.
     *
     * @return list<mixed>
     *
     * @throws InvalidToolRegistryException
     */
    private function recordedGaps(string $systemPrompt, string $userMessage): array
    {
        $coverageGapCollector = new CoverageGapCollector();
        $recordingToolReach = new RecordingToolReach();
        $toolRegistry = new ToolRegistry([$recordingToolReach->track($this->recordCoverageGapToolFactory->create($coverageGapCollector))], $this->logger);
        $recordingToolReach->handOver();

        $llmResponse = $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->coverageCriticSettings->maxGaps + 1);

        return $recordingToolReach->reached() ? $coverageGapCollector->drain() : $this->answeredGaps($llmResponse);
    }

    /**
     * @return list<mixed>
     */
    private function answeredGaps(LLMResponse $llmResponse): array
    {
        return array_values($llmResponse->parseJson());
    }
}
