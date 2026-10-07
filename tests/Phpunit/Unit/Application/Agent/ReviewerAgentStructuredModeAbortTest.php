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

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;

final class ReviewerAgentStructuredModeAbortTest extends TestCase
{
    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/reviewer_agent_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_single_review_preserves_a_verdict_recorded_before_a_later_round_of_the_same_review_aborts_on_budget_exceeded(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', [
                    'id' => $vulnerability->id(),
                    'accepted' => true,
                    'reviewer_notes' => 'recorded before the abort',
                ]);

                throw BudgetExceededException::forTokens(10, 5);
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $budgetExceeded = false;
        try {
            $reviewerAgent->review([$vulnerability], [], $auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The reviewer must rethrow BudgetExceededException.');
        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated']],
            $auditContext->coverage(),
        );
        self::assertSame(
            [['file' => 'src/A.php', 'validated' => true]],
            array_map($this->reviewedFindingShape(...), $auditContext->drainReviewedFindings()),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_single_review_marks_findings_not_yet_reached_aborted_on_budget_exceeded_mid_run(): void
    {
        $vulnerabilities = [
            $this->makeVulnerabilityAt('src/A.php'),
            $this->makeVulnerabilityAt('src/B.php'),
            $this->makeVulnerabilityAt('src/C.php'),
        ];

        $callCount = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use (&$callCount, $vulnerabilities): LLMResponse {
                ++$callCount;
                if (2 === $callCount) {
                    throw BudgetExceededException::forTokens(500, 100);
                }

                $toolRegistry->execute('record_review', ['id' => $vulnerabilities[0]->id(), 'accepted' => true]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $budgetExceeded = false;
        try {
            $reviewerAgent->review($vulnerabilities, [], $auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The reviewer must rethrow BudgetExceededException.');
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'aborted'],
                ['stage' => 'reviewer', 'file' => 'src/C.php', 'status' => 'aborted'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(
            [['file' => 'src/A.php', 'validated' => true]],
            array_map($this->reviewedFindingShape(...), $auditContext->drainReviewedFindings()),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_single_review_marks_findings_not_yet_reached_errored_on_provider_exception_mid_run(): void
    {
        $vulnerabilities = [
            $this->makeVulnerabilityAt('src/A.php'),
            $this->makeVulnerabilityAt('src/B.php'),
            $this->makeVulnerabilityAt('src/C.php'),
        ];

        $callCount = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use (&$callCount, $vulnerabilities): LLMResponse {
                ++$callCount;
                if (2 === $callCount) {
                    throw new LLMProviderException('platform unreachable');
                }

                $toolRegistry->execute('record_review', ['id' => $vulnerabilities[0]->id(), 'accepted' => true]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $providerFailed = false;
        try {
            $reviewerAgent->review($vulnerabilities, [], $auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The reviewer must rethrow LLMProviderException.');
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/C.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(
            [['file' => 'src/A.php', 'validated' => true]],
            array_map($this->reviewedFindingShape(...), $auditContext->drainReviewedFindings()),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_collection_batch_preserves_a_verdict_recorded_before_the_batch_call_aborts_on_budget_exceeded(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $neverReached = $this->makeVulnerabilityAt('src/B.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                throw BudgetExceededException::forTokens(10, 5);
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
                useStructuredCollection: true,
            ),
        );

        $budgetExceeded = false;
        try {
            $reviewerAgent->review([$vulnerability, $neverReached], [], $auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The reviewer must rethrow BudgetExceededException.');
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'aborted'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(
            [['file' => 'src/A.php', 'validated' => true]],
            array_map($this->reviewedFindingShape(...), $auditContext->drainReviewedFindings()),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_concurrent_structured_review_preserves_a_verdict_recorded_before_the_whole_batch_call_aborts_on_budget_exceeded(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use ($vulnerability): array {
                self::registryOf($requests[0])->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                throw BudgetExceededException::forTokens(10, 5);
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
                useStructuredCollection: true,
            ),
        );

        $budgetExceeded = false;
        try {
            $reviewerAgent->review([$vulnerability], [], $auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The reviewer must rethrow BudgetExceededException.');
        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated']],
            $auditContext->coverage(),
        );
        self::assertSame(
            [['file' => 'src/A.php', 'validated' => true]],
            array_map($this->reviewedFindingShape(...), $auditContext->drainReviewedFindings()),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_concurrent_reviews_preserve_earlier_window_verdicts_and_mark_later_window_aborted_on_budget_exceeded(): void
    {
        $vulnerabilities = $this->makeVulnerabilitiesAt('src/A.php', 'src/B.php', 'src/C.php', 'src/D.php');

        $callCount = 0;
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$callCount, $vulnerabilities): array {
                ++$callCount;
                if (2 === $callCount) {
                    throw BudgetExceededException::forTokens(10, 5);
                }

                foreach ($requests as $position => $request) {
                    self::registryOf($request)->execute('record_review', ['id' => $vulnerabilities[$position]->id(), 'accepted' => true]);
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 2,
                useStructuredCollection: true,
            ),
        );

        $budgetExceeded = false;
        try {
            $reviewerAgent->review($vulnerabilities, [], $auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The reviewer must rethrow BudgetExceededException.');
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/C.php', 'status' => 'aborted'],
                ['stage' => 'reviewer', 'file' => 'src/D.php', 'status' => 'aborted'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(
            [
                ['file' => 'src/A.php', 'validated' => true],
                ['file' => 'src/B.php', 'validated' => true],
            ],
            array_map($this->reviewedFindingShape(...), $auditContext->drainReviewedFindings()),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_concurrent_reviews_preserve_earlier_window_verdicts_and_mark_later_window_errored_on_provider_exception(): void
    {
        $vulnerabilities = $this->makeVulnerabilitiesAt('src/A.php', 'src/B.php', 'src/C.php', 'src/D.php');

        $callCount = 0;
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$callCount, $vulnerabilities): array {
                ++$callCount;
                if (2 === $callCount) {
                    throw new LLMProviderException('platform unreachable');
                }

                foreach ($requests as $position => $request) {
                    self::registryOf($request)->execute('record_review', ['id' => $vulnerabilities[$position]->id(), 'accepted' => true]);
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 2,
                useStructuredCollection: true,
            ),
        );

        $providerFailed = false;
        try {
            $reviewerAgent->review($vulnerabilities, [], $auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The reviewer must rethrow LLMProviderException.');
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/C.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/D.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(
            [
                ['file' => 'src/A.php', 'validated' => true],
                ['file' => 'src/B.php', 'validated' => true],
            ],
            array_map($this->reviewedFindingShape(...), $auditContext->drainReviewedFindings()),
        );
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        return ReviewerAgentHarness::registryOf($request);
    }

    /**
     * @return array{file: string, validated: bool}
     */
    private function reviewedFindingShape(Vulnerability $vulnerability): array
    {
        return ReviewerAgentHarness::reviewedFindingShape($vulnerability);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerabilityAt(
        string $filePath,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
    ): Vulnerability {
        return ReviewerAgentHarness::vulnerabilityAt($filePath, $vulnerabilitySeverity);
    }

    /**
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerabilitiesAt(string ...$filePaths): array
    {
        return ReviewerAgentHarness::vulnerabilitiesAt(...$filePaths);
    }
}
