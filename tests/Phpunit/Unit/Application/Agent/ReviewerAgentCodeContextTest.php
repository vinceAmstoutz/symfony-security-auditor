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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingBatchLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;

final class ReviewerAgentCodeContextTest extends TestCase
{
    private const string AUDITED_PATH = 'src/Controller/Foo.php';

    private const string TOOL_PATH = 'src/Repository/FooRepository.php';

    private const string TOOL_MARKER = 'tool-scope-file-marker';

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_sequential_review_judges_a_finding_against_a_file_only_the_tools_can_open(): void
    {
        $recordingLLMClient = new RecordingLLMClient('{"accepted": true}');

        $this->review($recordingLLMClient, new ReviewerModeConfiguration(useStructuredCollection: false), false);

        self::assertCount(1, $recordingLLMClient->capturedUserMessages);
        self::assertStringContainsString(self::TOOL_MARKER, $recordingLLMClient->capturedUserMessages[0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_review_judges_a_finding_against_a_file_only_the_tools_can_open(): void
    {
        $recordingLLMClient = new RecordingLLMClient('');

        $this->review($recordingLLMClient, new ReviewerModeConfiguration(), true);

        self::assertCount(1, $recordingLLMClient->capturedUserMessages);
        self::assertStringContainsString(self::TOOL_MARKER, $recordingLLMClient->capturedUserMessages[0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_batched_review_judges_a_finding_against_a_file_only_the_tools_can_open(): void
    {
        $recordingLLMClient = new RecordingLLMClient('[]');

        $this->review($recordingLLMClient, new ReviewerModeConfiguration(batchSize: 2, useStructuredCollection: false), false);

        self::assertCount(1, $recordingLLMClient->capturedUserMessages);
        self::assertStringContainsString(self::TOOL_MARKER, $recordingLLMClient->capturedUserMessages[0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_concurrent_review_judges_a_finding_against_a_file_only_the_tools_can_open(): void
    {
        $recordingBatchLLMClient = new RecordingBatchLLMClient('{"accepted": true}');

        $this->review($recordingBatchLLMClient, new ReviewerModeConfiguration(maxConcurrent: 4, useStructuredCollection: false), false);

        self::assertCount(1, $recordingBatchLLMClient->capturedUserMessages);
        self::assertStringContainsString(self::TOOL_MARKER, $recordingBatchLLMClient->capturedUserMessages[0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_concurrent_structured_review_judges_a_finding_against_a_file_only_the_tools_can_open(): void
    {
        $recordingBatchLLMClient = new RecordingBatchLLMClient();

        $this->review($recordingBatchLLMClient, new ReviewerModeConfiguration(maxConcurrent: 4), true);

        self::assertCount(1, $recordingBatchLLMClient->capturedUserMessages);
        self::assertStringContainsString(self::TOOL_MARKER, $recordingBatchLLMClient->capturedUserMessages[0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_an_audited_file_is_judged_against_its_own_content_when_the_tool_scope_lists_it_too(): void
    {
        $recordingLLMClient = new RecordingLLMClient('{"accepted": true}');
        $audited = [ProjectFile::create(self::AUDITED_PATH, '/app/'.self::AUDITED_PATH, '<?php // audited-content')];
        $toolFiles = [ProjectFile::create(self::AUDITED_PATH, '/app/'.self::AUDITED_PATH, '<?php // tool-scope-content')];

        $this->reviewerAgent($recordingLLMClient, new ReviewerModeConfiguration(useStructuredCollection: false), false)
            ->review([ReviewerAgentHarness::vulnerabilityAt(self::AUDITED_PATH)], $audited, new NullCoverageRecorder(), toolFiles: $toolFiles);

        self::assertStringContainsString('audited-content', $recordingLLMClient->capturedUserMessages[0]);
        self::assertStringNotContainsString('tool-scope-content', $recordingLLMClient->capturedUserMessages[0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_outside_the_audited_files_is_judged_blind_when_no_tool_scope_is_named(): void
    {
        $recordingLLMClient = new RecordingLLMClient('{"accepted": true}');

        $this->reviewerAgent($recordingLLMClient, new ReviewerModeConfiguration(useStructuredCollection: false), false)
            ->review([ReviewerAgentHarness::vulnerabilityAt(self::TOOL_PATH)], [$this->auditedFile()], new NullCoverageRecorder());

        self::assertStringNotContainsString(self::TOOL_MARKER, $recordingLLMClient->capturedUserMessages[0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function review(LLMClientInterface $llmClient, ReviewerModeConfiguration $reviewerModeConfiguration, bool $structuredPrompt): void
    {
        $projectFile = $this->auditedFile();
        $toolOnly = ProjectFile::create(self::TOOL_PATH, '/app/'.self::TOOL_PATH, '<?php class FooRepository { /* '.self::TOOL_MARKER.' */ }');

        $this->reviewerAgent($llmClient, $reviewerModeConfiguration, $structuredPrompt)
            ->review([ReviewerAgentHarness::vulnerabilityAt(self::TOOL_PATH)], [$projectFile], new NullCoverageRecorder(), toolFiles: [$projectFile, $toolOnly]);
    }

    private function reviewerAgent(LLMClientInterface $llmClient, ReviewerModeConfiguration $reviewerModeConfiguration, bool $structuredPrompt): ReviewerAgent
    {
        return new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: $structuredPrompt),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            $reviewerModeConfiguration,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function auditedFile(): ProjectFile
    {
        return ProjectFile::create(self::AUDITED_PATH, '/app/'.self::AUDITED_PATH, '<?php class Foo {}');
    }
}
