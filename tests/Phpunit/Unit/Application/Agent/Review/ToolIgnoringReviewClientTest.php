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

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ToolIgnoringReviewClientTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_single_review_whose_client_never_offers_the_recording_tool_has_its_json_verdict_applied_and_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn($this->answer('{"accepted": true, "reviewer_notes": "confirmed"}'));
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->structuredReviewAnalyzer($llmClient, $reviewerCache)->analyze([$this->vulnerabilityAt('src/A.php')], [], $recordingCoverageRecorder, false);

        self::assertTrue($reviewed[0]->isReviewerValidated());
        self::assertSame([['stage' => 'reviewer', 'filePath' => 'src/A.php', 'status' => 'validated']], $recordingCoverageRecorder->coverage);
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
    public function test_a_single_review_whose_client_offers_the_recording_tool_has_its_answer_text_left_unread(): void
    {
        $answer = $this->answer('{"accepted": true}');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($answer): LLMResponse {
            $toolRegistry->definitions();

            return $answer;
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->structuredReviewAnalyzer($llmClient, new NullReviewerCache())->analyze([$this->vulnerabilityAt('src/A.php')], [], $recordingCoverageRecorder, false);

        self::assertFalse($reviewed[0]->isReviewerValidated());
        self::assertSame([['stage' => 'reviewer', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
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
    public function test_concurrent_reviews_whose_client_never_offers_the_recording_tool_have_their_json_verdicts_applied(): void
    {
        $answers = [$this->answer('{"accepted": true}'), $this->answer('{"accepted": false}')];
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturn($answers);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $reviewerVerdictCache = new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger());
        $concurrentStructuredReviewAnalyzer = new ConcurrentStructuredReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            $reviewerVerdictCache,
            new ReviewOutcomeRecorder(new VerdictApplier(new NullLogger()), $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            new RecordReviewToolFactory(),
            new NullLogger(),
            4,
            4,
            RecordingToolClients::forReviewer(new NullLogger()),
        );

        $reviewed = $concurrentStructuredReviewAnalyzer->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], $recordingCoverageRecorder, false);

        self::assertSame([true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'rejected'], array_column($recordingCoverageRecorder->coverage, 'status'));
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
    public function test_a_review_batch_whose_client_never_offers_the_recording_tool_has_its_json_verdicts_applied(): void
    {
        [$first, $second] = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn($this->answer((string) json_encode([['id' => $first->id(), 'accepted' => true], ['id' => $second->id(), 'accepted' => false]])));
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->batchReviewAnalyzer($llmClient, new NullLogger())->analyze([$first, $second], [], new ReviewBatchSettings(5, true, false, $recordingCoverageRecorder, null));

        self::assertSame([true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'rejected'], array_column($recordingCoverageRecorder->coverage, 'status'));
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
    public function test_a_review_batch_whose_client_never_offers_the_recording_tool_and_answers_prose_is_recorded_errored_as_unreadable(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn($this->answer('Both findings look real.'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error')->with('Failed to parse reviewer batch response', [
            'batch_size' => 2,
            'error' => 'Syntax error',
            'content_preview' => 'Both findings look real.',
        ]);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->batchReviewAnalyzer($llmClient, $logger)->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], new ReviewBatchSettings(5, true, false, $recordingCoverageRecorder, null));

        self::assertSame([false, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['errored', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function answer(string $content): LLMResponse
    {
        return LLMResponse::of($content, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
    }

    private function structuredReviewAnalyzer(LLMClientInterface $llmClient, ReviewerCacheInterface $reviewerCache): StructuredReviewAnalyzer
    {
        $reviewerVerdictCache = new ReviewerVerdictCache($reviewerCache, new NullLogger());

        return new StructuredReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            $reviewerVerdictCache,
            new ReviewOutcomeRecorder(new VerdictApplier(new NullLogger()), $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            new RecordReviewToolFactory(),
            new NullLogger(),
            4,
            RecordingToolClients::forReviewer(new NullLogger()),
        );
    }

    private function batchReviewAnalyzer(LLMClientInterface $llmClient, LoggerInterface $logger): BatchReviewAnalyzer
    {
        $verdictApplier = new VerdictApplier(new NullLogger());
        $reviewerVerdictCache = new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger());

        return new BatchReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new BatchVerdictApplier($verdictApplier, $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            $reviewerVerdictCache,
            new ReviewOutcomeRecorder($verdictApplier, $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            $logger,
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
