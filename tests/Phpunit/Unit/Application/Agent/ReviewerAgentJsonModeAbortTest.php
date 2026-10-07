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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;

final class ReviewerAgentJsonModeAbortTest extends TestCase
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
    public function test_sequential_review_marks_findings_not_yet_reached_aborted_on_budget_exceeded_mid_run(): void
    {
        $vulnerabilities = [
            $this->makeVulnerabilityAt('src/A.php'),
            $this->makeVulnerabilityAt('src/B.php'),
            $this->makeVulnerabilityAt('src/C.php'),
        ];

        $callCount = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function () use (&$callCount): LLMResponse {
                ++$callCount;
                if (2 === $callCount) {
                    throw BudgetExceededException::forTokens(500, 100);
                }

                return LLMResponse::of('{"accepted": true}', 'claude', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

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
    public function test_sequential_review_marks_findings_not_yet_reached_errored_on_provider_exception_mid_run(): void
    {
        $vulnerabilities = [
            $this->makeVulnerabilityAt('src/A.php'),
            $this->makeVulnerabilityAt('src/B.php'),
            $this->makeVulnerabilityAt('src/C.php'),
        ];

        $callCount = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function () use (&$callCount): LLMResponse {
                ++$callCount;
                if (2 === $callCount) {
                    throw new LLMProviderException('platform unreachable');
                }

                return LLMResponse::of('{"accepted": true}', 'claude', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

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
    public function test_batch_mode_marks_findings_in_batches_not_yet_reached_aborted_on_budget_exceeded_mid_run(): void
    {
        $vulnerabilities = $this->makeVulnerabilitiesAt('src/A.php', 'src/B.php', 'src/C.php', 'src/D.php', 'src/E.php', 'src/F.php');

        $batch1Response = (string) json_encode([
            ['id' => $vulnerabilities[0]->id(), 'accepted' => true],
            ['id' => $vulnerabilities[1]->id(), 'accepted' => true],
        ]);

        $callCount = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function () use (&$callCount, $batch1Response): LLMResponse {
                ++$callCount;
                if (2 === $callCount) {
                    throw BudgetExceededException::forTokens(500, 100);
                }

                return LLMResponse::of($batch1Response, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 2,
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
                ['stage' => 'reviewer', 'file' => 'src/E.php', 'status' => 'aborted'],
                ['stage' => 'reviewer', 'file' => 'src/F.php', 'status' => 'aborted'],
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
    public function test_batch_mode_marks_findings_in_batches_not_yet_reached_errored_on_provider_exception_mid_run(): void
    {
        $vulnerabilities = $this->makeVulnerabilitiesAt('src/A.php', 'src/B.php', 'src/C.php', 'src/D.php', 'src/E.php', 'src/F.php');

        $batch1Response = (string) json_encode([
            ['id' => $vulnerabilities[0]->id(), 'accepted' => true],
            ['id' => $vulnerabilities[1]->id(), 'accepted' => true],
        ]);

        $callCount = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function () use (&$callCount, $batch1Response): LLMResponse {
                ++$callCount;
                if (2 === $callCount) {
                    throw new LLMProviderException('platform unreachable');
                }

                return LLMResponse::of($batch1Response, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 2,
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
                ['stage' => 'reviewer', 'file' => 'src/E.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/F.php', 'status' => 'errored'],
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
    public function test_concurrent_review_preserves_earlier_window_verdicts_and_marks_later_window_aborted_on_budget_exceeded(): void
    {
        $vulnerabilities = [
            $this->makeVulnerabilityAt('src/A.php'),
            $this->makeVulnerabilityAt('src/B.php'),
            $this->makeVulnerabilityAt('src/C.php'),
            $this->makeVulnerabilityAt('src/D.php'),
        ];

        $callCount = 0;
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('completeBatch')
            ->willReturnCallback(static function (array $requests) use (&$callCount): array {
                ++$callCount;
                if (2 === $callCount) {
                    throw BudgetExceededException::forTokens(500, 100);
                }

                return array_map(
                    static fn (): LLMResponse => LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                    $requests,
                );
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 2,
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
    public function test_concurrent_review_preserves_earlier_window_verdicts_and_marks_later_window_errored_on_provider_exception(): void
    {
        $vulnerabilities = [
            $this->makeVulnerabilityAt('src/A.php'),
            $this->makeVulnerabilityAt('src/B.php'),
            $this->makeVulnerabilityAt('src/C.php'),
            $this->makeVulnerabilityAt('src/D.php'),
        ];

        $callCount = 0;
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('completeBatch')
            ->willReturnCallback(static function (array $requests) use (&$callCount): array {
                ++$callCount;
                if (2 === $callCount) {
                    throw new LLMProviderException('platform unreachable');
                }

                return array_map(
                    static fn (): LLMResponse => LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                    $requests,
                );
            });

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 2,
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

    private function makeReviewerAgent(LLMClientInterface $llmClient): ReviewerAgent
    {
        return ReviewerAgentHarness::reviewerAgent($llmClient);
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
