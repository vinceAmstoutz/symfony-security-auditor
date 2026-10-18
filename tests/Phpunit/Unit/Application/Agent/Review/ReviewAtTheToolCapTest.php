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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordingToolClients;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchVerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentStructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewBatchSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\StructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingTriageMemory;

final class ReviewAtTheToolCapTest extends TestCase
{
    private const string PARTIAL_LOOK = 'Probably sanitized by a service it could not open before the round limit';

    private RecordingReviewerCache $recordingReviewerCache;

    private ReviewerVerdictCache $reviewerVerdictCache;

    private RecordingTriageMemory $recordingTriageMemory;

    #[Override]
    protected function setUp(): void
    {
        $this->recordingTriageMemory = new RecordingTriageMemory();
        $this->recordingReviewerCache = new RecordingReviewerCache();
        $this->reviewerVerdictCache = new ReviewerVerdictCache($this->recordingReviewerCache, new NullLogger());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_verdict_recorded_at_the_tool_cap_is_applied_but_neither_cached_nor_remembered(): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
            $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => false, 'reviewer_notes' => self::PARTIAL_LOOK]);

            return self::cappedAnswer('');
        });

        $reviewed = $this->structuredAnalyzer($llmClient)->analyze([$vulnerability], [], new NullCoverageRecorder(), false);

        self::assertSame([false, [], []], [$reviewed[0]->isReviewerValidated(), $this->recordingReviewerCache->stored, $this->recordingTriageMemory->reasons]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_verdict_answered_at_the_tool_cap_is_applied_but_neither_cached_nor_remembered(): void
    {
        $vulnerability = $this->reviewOutcomeRecorder()->applyResponse($this->vulnerabilityAt('src/A.php'), self::cappedAnswer((string) json_encode(['accepted' => false, 'reviewer_notes' => self::PARTIAL_LOOK])), new NullCoverageRecorder(), 'code-context');

        self::assertSame([false, [], []], [$vulnerability->isReviewerValidated(), $this->recordingReviewerCache->stored, $this->recordingTriageMemory->reasons]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_verdict_a_window_member_recorded_at_the_tool_cap_is_applied_but_neither_cached_nor_remembered(): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests) use ($vulnerability): array {
            self::assertIsArray($requests[0]);
            self::assertInstanceOf(ToolRegistry::class, $requests[0]['tools']);
            $requests[0]['tools']->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => false, 'reviewer_notes' => self::PARTIAL_LOOK]);

            return [self::cappedAnswer('')];
        });
        $concurrentStructuredReviewAnalyzer = new ConcurrentStructuredReviewAnalyzer($llmClient, new ReviewerPromptBuilder(useStructuredCollection: true), $this->reviewerVerdictCache, $this->reviewOutcomeRecorder(), new RecordReviewToolFactory(), new NullLogger(), 4, 4, RecordingToolClients::forReviewer(new NullLogger()));

        $reviewed = $concurrentStructuredReviewAnalyzer->analyze([$vulnerability], [], new NullCoverageRecorder(), false);

        self::assertSame([false, [], []], [$reviewed[0]->isReviewerValidated(), $this->recordingReviewerCache->stored, $this->recordingTriageMemory->reasons]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_batch_answered_at_the_tool_cap_is_applied_but_neither_cached_nor_remembered(): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(self::cappedAnswer((string) json_encode([['id' => $vulnerability->id(), 'accepted' => false, 'reviewer_notes' => self::PARTIAL_LOOK]])));

        $reviewed = $this->batchAnalyzer($llmClient)->analyze([$vulnerability], [], new ReviewBatchSettings(5, false, false, new NullCoverageRecorder(), new ToolRegistry([], new NullLogger())));

        self::assertSame([false, [], []], [$reviewed[0]->isReviewerValidated(), $this->recordingReviewerCache->stored, $this->recordingTriageMemory->reasons]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_batch_recorded_at_the_tool_cap_is_applied_but_neither_cached_nor_remembered(): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
            $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => false, 'reviewer_notes' => self::PARTIAL_LOOK]);

            return self::cappedAnswer('');
        });

        $reviewed = $this->batchAnalyzer($llmClient)->analyze([$vulnerability], [], new ReviewBatchSettings(5, true, false, new NullCoverageRecorder(), null));

        self::assertSame([false, [], []], [$reviewed[0]->isReviewerValidated(), $this->recordingReviewerCache->stored, $this->recordingTriageMemory->reasons]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_rejection_a_batch_recorded_before_its_conversation_failed_is_remembered(): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
            $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => false, 'reviewer_notes' => self::PARTIAL_LOOK]);

            throw new RuntimeException('the conversation broke after recording');
        });

        $this->batchAnalyzer($llmClient)->analyze([$vulnerability], [], new ReviewBatchSettings(5, true, false, new NullCoverageRecorder(), null));

        self::assertSame([self::PARTIAL_LOOK], $this->recordingTriageMemory->reasons);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function cappedAnswer(string $content): LLMResponse
    {
        return LLMResponse::of($content, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))->withReachedToolCap();
    }

    private function reviewOutcomeRecorder(): ReviewOutcomeRecorder
    {
        return new ReviewOutcomeRecorder(new VerdictApplier(new NullLogger()), $this->reviewerVerdictCache, new NullLogger(), new NullProgressReporter(), $this->recordingTriageMemory);
    }

    private function structuredAnalyzer(LLMClientInterface $llmClient): StructuredReviewAnalyzer
    {
        return new StructuredReviewAnalyzer($llmClient, new ReviewerPromptBuilder(useStructuredCollection: true), $this->reviewerVerdictCache, $this->reviewOutcomeRecorder(), new RecordReviewToolFactory(), new NullLogger(), 4, RecordingToolClients::forReviewer(new NullLogger()));
    }

    private function batchAnalyzer(LLMClientInterface $llmClient): BatchReviewAnalyzer
    {
        $verdictApplier = new VerdictApplier(new NullLogger());

        return new BatchReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new BatchVerdictApplier($verdictApplier, $this->reviewerVerdictCache, new NullLogger(), new NullProgressReporter(), $this->recordingTriageMemory),
            $this->reviewerVerdictCache,
            $this->reviewOutcomeRecorder(),
            new NullLogger(),
            4,
            new RecordReviewToolFactory(),
            RecordingToolClients::forReviewer(new NullLogger()),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerabilityAt(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::HIGH, 'Test '.$filePath, 0.9),
            new CodeLocation($filePath, 1, 5),
            new VulnerabilityNarrative('Test', 'vec', 'proof', 'fix'),
            'code',
        );
    }
}
