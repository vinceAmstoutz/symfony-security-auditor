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
use Psr\Log\NullLogger;
use RuntimeException;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class StructuredReviewAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_bypass_cache_does_not_store_a_verdict_recovered_after_a_throwable(): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::never())->method('store');
        $reviewerVerdictCache = new ReviewerVerdictCache($reviewerCache, new NullLogger());

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                throw new RuntimeException('transport dropped after recording');
            },
        );

        $verdictApplier = new VerdictApplier(new NullLogger());
        $structuredReviewAnalyzer = new StructuredReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            $reviewerVerdictCache,
            new ReviewOutcomeRecorder($verdictApplier, $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            new RecordReviewToolFactory(),
            new NullLogger(),
            4,
        );

        $reviewed = $structuredReviewAnalyzer->analyze([$vulnerability], [], new NullCoverageRecorder(), true);

        self::assertTrue($reviewed[0]->isReviewerValidated());
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_review_stopped_at_the_tool_cap_without_a_verdict_is_errored_not_rejected_and_not_cached(): void
    {
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::never())->method('store');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1)));
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient, new ReviewerVerdictCache($reviewerCache, new NullLogger()))->analyze([$this->vulnerabilityAt('src/A.php')], [], $recordingCoverageRecorder, false);

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
     */
    public function test_a_verdict_recorded_before_the_tool_cap_is_applied_and_cached(): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())->method('store');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1));
            },
        );

        $reviewed = $this->analyzer($llmClient, new ReviewerVerdictCache($reviewerCache, new NullLogger()))->analyze([$vulnerability], [], new NullCoverageRecorder(), false);

        self::assertTrue($reviewed[0]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_the_model_cannot_fit_is_errored_and_the_review_goes_on_with_the_next_one(): void
    {
        [$oversized, $next] = [$this->vulnerabilityAt('src/Huge.php'), $this->vulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $system, string $user, ToolRegistry $toolRegistry) use ($oversized, $next): LLMResponse {
                if (str_contains($user, $oversized->id())) {
                    throw new LLMRequestTooLargeException('prompt is too long');
                }

                $toolRegistry->execute('record_review', ['id' => $next->id(), 'accepted' => true]);

                return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            },
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient, new ReviewerVerdictCache(self::createStub(ReviewerCacheInterface::class), new NullLogger()))->analyze([$oversized, $next], [], $recordingCoverageRecorder, false);

        self::assertSame([false, true], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['errored', 'validated'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    private function analyzer(LLMClientInterface $llmClient, ReviewerVerdictCache $reviewerVerdictCache): StructuredReviewAnalyzer
    {
        $verdictApplier = new VerdictApplier(new NullLogger());

        return new StructuredReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            $reviewerVerdictCache,
            new ReviewOutcomeRecorder($verdictApplier, $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            new RecordReviewToolFactory(),
            new NullLogger(),
            4,
        );
    }
}
