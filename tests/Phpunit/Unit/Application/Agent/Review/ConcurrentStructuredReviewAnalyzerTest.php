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
use Stringable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentStructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ConcurrentStructuredReviewAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_it_dispatches_one_request_per_window_when_max_concurrent_is_one(): void
    {
        $batchSizes = [];
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(
            static function (array $requests) use (&$batchSizes): array {
                $batchSizes[] = \count($requests);

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            },
        );

        $concurrentStructuredReviewAnalyzer = new ConcurrentStructuredReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            $this->reviewOutcomeRecorder(),
            new RecordReviewToolFactory(),
            new NullLogger(),
            1,
            4,
        );

        $concurrentStructuredReviewAnalyzer->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], new NullCoverageRecorder(), false);

        self::assertSame([1, 1], $batchSizes);
    }

    private function reviewOutcomeRecorder(): ReviewOutcomeRecorder
    {
        return new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            new NullProgressReporter(),
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_window_member_that_recorded_no_verdict_is_errored_whether_it_hit_the_tool_cap_or_ended_normally(): void
    {
        $vulnerabilities = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php'), $this->vulnerabilityAt('src/C.php'), $this->vulnerabilityAt('src/D.php')];
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests) use ($vulnerabilities): array {
            self::registryOf($requests[0])->execute('record_review', ['id' => $vulnerabilities[0]->id(), 'accepted' => true]);
            self::registryOf($requests[2])->execute('record_review', ['id' => $vulnerabilities[2]->id(), 'accepted' => true]);

            return [
                LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1)),
                LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1)),
                LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
            ];
        });
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::exactly(2))->method('store');
        $reviewerVerdictCache = new ReviewerVerdictCache($reviewerCache, new NullLogger());
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $warnings = [];
        $outcomeLogger = self::createStub(LoggerInterface::class);
        $outcomeLogger->method('warning')->willReturnCallback(static function (string|Stringable $message, array $context = []) use (&$warnings): void {
            $warnings[] = [(string) $message, $context];
        });
        $concurrentStructuredReviewAnalyzer = new ConcurrentStructuredReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            $reviewerVerdictCache,
            new ReviewOutcomeRecorder(new VerdictApplier(new NullLogger()), $reviewerVerdictCache, $outcomeLogger, new NullProgressReporter()),
            new RecordReviewToolFactory(),
            new NullLogger(),
            4,
            4,
        );

        $reviewed = $concurrentStructuredReviewAnalyzer->analyze($vulnerabilities, [], $recordingCoverageRecorder, false);

        self::assertSame([true, false, true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(
            [
                ['stage' => 'reviewer', 'filePath' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'filePath' => 'src/B.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'filePath' => 'src/C.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'filePath' => 'src/D.php', 'status' => 'errored'],
            ],
            $recordingCoverageRecorder->coverage,
        );
        self::assertSame(
            [
                ['Reviewer response was cut short; the finding is recorded as errored and left out of the cache', ['vulnerability_id' => $vulnerabilities[1]->id(), 'stop_reason' => 'max_tool_iterations']],
                ['Reviewer reached no verdict for the finding; it is recorded as errored and left out of the cache', ['vulnerability_id' => $vulnerabilities[3]->id()]],
            ],
            $warnings,
        );
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        self::assertIsArray($request);
        $toolRegistry = $request['tools'] ?? null;
        self::assertInstanceOf(ToolRegistry::class, $toolRegistry);

        return $toolRegistry;
    }
}
