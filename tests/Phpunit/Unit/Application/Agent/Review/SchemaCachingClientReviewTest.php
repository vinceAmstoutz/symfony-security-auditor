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

use Closure;
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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;

final class SchemaCachingClientReviewTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_client_that_offered_the_tool_schemas_it_built_once_has_a_later_unrecorded_review_errored_as_before(): void
    {
        [$first, $second] = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback($this->schemaCachingClientRecording($first, '{"accepted": true}'));
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->structuredReviewAnalyzer($llmClient, new NullReviewerCache())->analyze([$first, $second], [], $recordingCoverageRecorder, false);

        self::assertSame([true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_review_batch_client_that_offered_the_tool_schemas_it_built_once_has_a_later_unrecorded_batch_errored_as_before(): void
    {
        [$first, $second] = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback($this->schemaCachingClientRecording($first, (string) json_encode([['id' => $second->id(), 'accepted' => true]])));
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->batchReviewAnalyzer($llmClient, new NullLogger())->analyze([$first, $second], [], new ReviewBatchSettings(1, true, false, $recordingCoverageRecorder, null));

        self::assertSame([true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_batch_client_that_offered_the_tool_schemas_of_its_first_request_only_has_every_unrecorded_review_errored_as_before(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(function (array $requests): array {
            ReviewerAgentHarness::registryOf($requests[0])->definitions();

            return array_fill(0, \count($requests), $this->answer('{"accepted": true}'));
        });
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

        $concurrentStructuredReviewAnalyzer->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], $recordingCoverageRecorder, false);

        self::assertSame(['errored', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * The first call reads the tool schemas and records a verdict for `$vulnerability`; every later one answers `$laterAnswer` and calls no tool.
     *
     * @return Closure(string, string, ToolRegistry): LLMResponse
     */
    private function schemaCachingClientRecording(Vulnerability $vulnerability, string $laterAnswer): Closure
    {
        $schemas = null;

        return function (string $system, string $user, ToolRegistry $toolRegistry) use (&$schemas, $vulnerability, $laterAnswer): LLMResponse {
            if (null === $schemas) {
                $schemas = $toolRegistry->definitions();
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return $this->answer('');
            }

            return $this->answer($laterAnswer);
        };
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
