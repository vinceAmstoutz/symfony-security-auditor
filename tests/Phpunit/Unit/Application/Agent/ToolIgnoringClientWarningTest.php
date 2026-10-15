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

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class ToolIgnoringClientWarningTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_an_attacker_whose_client_ignores_the_tools_warns_once_naming_the_setting_to_turn_off(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $warningCollectingLogger = new WarningCollectingLogger();
        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                llmClient: $llmClient,
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                codeSlicer: new NullCodeSlicer(),
                recordVulnerabilityToolFactory: new RecordVulnerabilityToolFactory(),
            ),
            new AttackerScanCollaborators(new NullAttackerCache(), new NullStaticPreScanner(), new NullProgressReporter(), new FileChunker(ChunkingStrategy::Type, 1)),
            new AttackerAnalysisSettings(toolsEnabled: false, useStructuredCollection: true),
            $warningCollectingLogger,
        );

        $attackerAgent->analyze(new AttackerAnalysisRequest([ChunkAnalysisInputs::file('src/A.php'), ChunkAnalysisInputs::file('src/B.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())), new NullCoverageRecorder());

        self::assertSame(['The LLM client never offered the record_vulnerability tool to the model, so its answers are read as JSON; set audit.structured_collection: false for a client that ignores tools.'], array_column($warningCollectingLogger->warnings, 0));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidTokenUsageException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_reviewer_whose_client_ignores_the_tools_warns_once_naming_the_setting_to_turn_off(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $warningCollectingLogger = new WarningCollectingLogger();
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($llmClient, new ReviewerPromptBuilder(useStructuredCollection: true), $warningCollectingLogger, new RecordReviewToolFactory()),
            new ReviewerModeConfiguration(useStructuredCollection: true),
        );

        $reviewerAgent->review([ReviewerAgentHarness::vulnerabilityAt('src/A.php'), ReviewerAgentHarness::vulnerabilityAt('src/B.php')], [], new NullCoverageRecorder());

        self::assertSame(['The LLM client never offered the record_review tool to the model, so its answers are read as JSON; set audit.reviewer_structured_collection: false for a client that ignores tools.'], array_column($warningCollectingLogger->warnings, 0));
    }
}
