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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;

final class ReviewerAgentTest extends TestCase
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    private string $tmpDir;

    public function test_it_returns_empty_array_when_no_vulnerabilities(): void
    {
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([], [], new NullCoverageRecorder());

        self::assertEmpty($result);
    }

    public function test_it_marks_vulnerability_as_validated_when_accepted(): void
    {
        $vulnerability = $this->makeVulnerability();
        $files = [$this->makeFile('src/Controller/UserController.php')];

        $reviewResponse = (string) json_encode([
            'id' => $vulnerability->id(),
            'accepted' => true,
            'adjusted_severity' => null,
            'reviewer_notes' => 'Confirmed: no access control on this route',
            'additional_attack_paths' => null,
        ]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], $files, new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_it_marks_vulnerability_as_not_validated_when_rejected(): void
    {
        $vulnerability = $this->makeVulnerability();

        $reviewResponse = (string) json_encode([
            'id' => $vulnerability->id(),
            'accepted' => false,
            'adjusted_severity' => null,
            'reviewer_notes' => 'False positive: Symfony firewall protects this route',
            'additional_attack_paths' => null,
        ]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_adjusts_severity_when_reviewer_upgrades(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH);

        $reviewResponse = (string) json_encode([
            'id' => $vulnerability->id(),
            'accepted' => true,
            'adjusted_severity' => 'critical',
            'reviewer_notes' => 'Impact is worse than initially assessed',
            'additional_attack_paths' => null,
        ]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[0]->severity());
    }

    public function test_it_handles_invalid_adjusted_severity_gracefully(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH);

        $reviewResponse = (string) json_encode([
            'id' => $vulnerability->id(),
            'accepted' => true,
            'adjusted_severity' => 'SUPER_CRITICAL_9000',
            'reviewer_notes' => 'Bad severity',
        ]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        // Should still accept, just keep original severity
        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::HIGH, $result[0]->severity());
    }

    public function test_it_handles_parse_error_by_rejecting(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of('not json!!!', 'claude', 'end_turn', TokenUsageSnapshot::of(100, 10)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_handles_llm_exception_by_rejecting(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willThrowException(new RuntimeException('Network error'));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_handles_empty_llm_response_by_rejecting(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(100, 0)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_returns_all_reviewed_vulnerabilities_including_rejected(): void
    {
        $vulnerability = $this->makeVulnerability();
        $vuln2 = $this->makeVulnerability(VulnerabilitySeverity::MEDIUM);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('complete')
            ->willReturnOnConsecutiveCalls(
                LLMResponse::of((string) json_encode(['accepted' => true, 'reviewer_notes' => 'confirmed']), 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)),
                LLMResponse::of((string) json_encode(['accepted' => false, 'reviewer_notes' => 'false positive']), 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)),
            );
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability, $vuln2], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
    }

    public function test_it_handles_nested_array_review_response_format(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH);

        // LLM returns [[{...}]] — array wrapping an array
        $reviewResponse = (string) json_encode([[
            'accepted' => true,
            'adjusted_severity' => 'critical',
            'reviewer_notes' => 'Confirmed and upgraded',
        ]]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[0]->severity());
    }

    public function test_it_uses_empty_context_when_file_not_found_in_project_files(): void
    {
        $vulnerability = $this->makeVulnerability();
        $files = [
            $this->makeFile('src/Controller/OtherController.php'),
        ];

        $capturedUserMessage = null;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $sys, string $user) use (&$capturedUserMessage): LLMResponse {
                $capturedUserMessage = $user;

                return LLMResponse::of((string) json_encode(['accepted' => false]), 'claude', 'end_turn', TokenUsageSnapshot::of(100, 10));
            });
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $reviewerAgent->review([$vulnerability], $files, new NullCoverageRecorder());

        // vulnerability filePath is UserController.php — not in $files (OtherController.php)
        // Full File Context section should be empty
        self::assertStringContainsString('## Full File Context', (string) $capturedUserMessage);
        self::assertStringNotContainsString('class OtherController', (string) $capturedUserMessage);
    }

    public function test_it_finds_file_context_for_vulnerability(): void
    {
        $vulnerability = $this->makeVulnerability();
        $fileContent = '<?php class UserController { public function edit() {} }';
        $files = [
            ProjectFile::create(
                'src/Controller/UserController.php',
                '/app/src/Controller/UserController.php',
                $fileContent,
            ),
        ];

        $capturedUserMessage = null;

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(static function (string $sys, string $user) use (&$capturedUserMessage): LLMResponse {
                $capturedUserMessage = $user;

                return LLMResponse::of((string) json_encode(['accepted' => false, 'reviewer_notes' => 'ok']), 'claude', 'end_turn', TokenUsageSnapshot::of(100, 10));
            });
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $reviewerAgent->review([$vulnerability], $files, new NullCoverageRecorder());

        self::assertStringContainsString('UserController', (string) $capturedUserMessage);
    }

    public function test_it_logs_info_when_starting_review(): void
    {
        $loggedMessages = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message) use (&$loggedMessages): void {
                $loggedMessages[] = $message;
            },
        );

        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertContains('Reviewer agent validating findings', $loggedMessages);
    }

    public function test_it_does_not_log_info_when_no_vulnerabilities(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('info');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([], [], new NullCoverageRecorder());

        self::assertSame([], $result);
    }

    public function test_it_logs_error_with_specific_message_on_json_parse_failure(): void
    {
        $vulnerability = $this->makeVulnerability();

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with('Failed to parse reviewer response', [
                'vulnerability_id' => $vulnerability->id(),
                'error' => 'Syntax error',
                'content_preview' => 'invalid json {{{',
            ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('invalid json {{{', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_truncates_long_content_in_single_mode_parse_failure_log(): void
    {
        // Pin the truncation boundary so IncrementInteger / DecrementInteger
        // mutations on the byte-cap constant are killed.
        $errorLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug');
        $logger->method('error')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$errorLogs): void {
                $errorLogs[] = [$msg, $ctx];
            },
        );

        $longInvalidContent = str_repeat('y', self::PARSE_FAILURE_PREVIEW_BYTES * 2).' {{{';

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($longInvalidContent, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$this->makeVulnerability()], [], new NullCoverageRecorder());

        $singleParseLogs = array_values(array_filter(
            $errorLogs,
            static fn (array $entry): bool => 'Failed to parse reviewer response' === $entry[0],
        ));

        self::assertCount(1, $singleParseLogs);
        $preview = $singleParseLogs[0][1]['content_preview'];
        self::assertIsString($preview);
        self::assertSame(self::PARSE_FAILURE_PREVIEW_BYTES, \strlen($preview));
        self::assertSame(str_repeat('y', self::PARSE_FAILURE_PREVIEW_BYTES), $preview);
    }

    public function test_it_truncates_long_content_in_batch_mode_parse_failure_log(): void
    {
        // Same boundary pin for the batch path (separate constant on the
        // class even though both currently equal 512).
        $errorLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug');
        $logger->method('error')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$errorLogs): void {
                $errorLogs[] = [$msg, $ctx];
            },
        );

        $longInvalidContent = str_repeat('z', self::PARSE_FAILURE_PREVIEW_BYTES * 2).' {{{';

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($longInvalidContent, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $reviewerAgent->review(
            [$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')],
            [],
            new NullCoverageRecorder(),
        );

        $batchParseLogs = array_values(array_filter(
            $errorLogs,
            static fn (array $entry): bool => 'Failed to parse reviewer batch response' === $entry[0],
        ));

        self::assertCount(1, $batchParseLogs);
        $preview = $batchParseLogs[0][1]['content_preview'];
        self::assertIsString($preview);
        self::assertSame(self::PARSE_FAILURE_PREVIEW_BYTES, \strlen($preview));
        self::assertSame(str_repeat('z', self::PARSE_FAILURE_PREVIEW_BYTES), $preview);
    }

    public function test_it_logs_error_with_specific_message_on_llm_throwable(): void
    {
        $vulnerability = $this->makeVulnerability();

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with('Reviewer LLM call failed', [
                'vulnerability_id' => $vulnerability->id(),
                'error' => 'Timeout',
            ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new RuntimeException('Timeout'));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_logs_info_start_and_complete_with_exact_context(): void
    {
        $vulnerability = $this->makeVulnerability();
        $infoLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true, 'reviewer_notes' => 'confirmed']), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(['Reviewer agent validating findings', ['count' => 1, 'batch_size' => 1, 'tools_enabled' => false, 'structured_collection' => false]], $infoLogs[0]);
        self::assertSame(['Reviewer agent complete', ['reviewed' => 1, 'accepted' => 1, 'rejected' => 0]], $infoLogs[1]);
    }

    public function test_rejected_count_is_reviewed_minus_accepted(): void
    {
        $vulnerability = $this->makeVulnerability();
        $infoLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => false, 'reviewer_notes' => 'rejected']), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(['Reviewer agent complete', ['reviewed' => 1, 'accepted' => 0, 'rejected' => 1]], $infoLogs[1]);
    }

    public function test_it_logs_debug_review_decision_with_exact_context(): void
    {
        $vulnerability = $this->makeVulnerability();
        $debugLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true, 'reviewer_notes' => 'looks good']), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $debugLogs);
        self::assertSame('Vulnerability reviewed', $debugLogs[0][0]);
        self::assertSame([
            'id' => $vulnerability->id(),
            'accepted' => true,
            'notes' => 'looks good',
        ], $debugLogs[0][1]);
    }

    public function test_it_does_not_log_error_for_empty_llm_response(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('error');
        $logger->method('info');
        $logger->method('debug');

        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_logs_debug_invalid_severity_with_exact_context(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH);
        $debugLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true, 'adjusted_severity' => 'SUPER_CRITICAL_9000']), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        $invalidSeverityLog = array_filter($debugLogs, static fn (array $entry): bool => str_contains($entry[0], 'invalid severity'));
        self::assertNotEmpty($invalidSeverityLog);
        $entry = array_values($invalidSeverityLog)[0];
        self::assertSame(['adjusted_severity' => 'SUPER_CRITICAL_9000'], $entry[1]);
    }

    public function test_it_rejects_vulnerability_when_accepted_key_is_missing(): void
    {
        // Tests the `?? false` fallback: if 'accepted' key is absent, vulnerability must be rejected.
        // A FalseValue mutation would remove the `?? false`, making missing key produce null (truthy cast).
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['reviewer_notes' => 'no accepted key']), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_it_logs_debug_review_decision_when_finding_is_rejected(): void
    {
        $vulnerability = $this->makeVulnerability();
        $debugLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => false, 'reviewer_notes' => 'false positive']), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        $reviewedLogs = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => 'Vulnerability reviewed' === $entry[0],
        ));

        self::assertCount(1, $reviewedLogs);
        self::assertSame([
            'id' => $vulnerability->id(),
            'accepted' => false,
            'notes' => 'false positive',
        ], $reviewedLogs[0][1]);
    }

    public function test_it_logs_debug_review_decision_when_severity_is_elevated(): void
    {
        // Covers MethodCallRemoval on the logReviewDecision call after severity elevation
        // (post-elevation path, not the early-return path).
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH);
        $debugLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode([
                'accepted' => true,
                'adjusted_severity' => 'critical',
                'reviewer_notes' => 'severity upgraded',
            ]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        $reviewedLogs = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => 'Vulnerability reviewed' === $entry[0],
        ));

        self::assertCount(1, $reviewedLogs);
        self::assertSame([
            'id' => $vulnerability->id(),
            'accepted' => true,
            'notes' => 'severity upgraded',
        ], $reviewedLogs[0][1]);
    }

    public function test_it_includes_actual_file_content_in_llm_message(): void
    {
        // Tests ReturnRemoval on getFileContext: if the return is removed, content is '' and
        // the file's actual source code would NOT appear in the LLM user message.
        $fileContent = '<?php class UserController { public function sensitiveAction() {} }';
        $files = [
            ProjectFile::create(
                'src/Controller/UserController.php',
                '/app/src/Controller/UserController.php',
                $fileContent,
            ),
        ];

        $vulnerability = $this->makeVulnerability();

        $capturedUserMessage = null;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnCallback(
                static function (string $sys, string $user) use (&$capturedUserMessage): LLMResponse {
                    $capturedUserMessage = $user;

                    return LLMResponse::of((string) json_encode(['accepted' => true]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10));
                },
            );
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $reviewerAgent->review([$vulnerability], $files, new NullCoverageRecorder());

        self::assertStringContainsString('sensitiveAction', (string) $capturedUserMessage);
    }

    public function test_batch_mode_sends_single_llm_call_for_multiple_vulnerabilities(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');
        $c = $this->makeVulnerabilityAt('src/C.php');

        $batchResponse = (string) json_encode([
            ['id' => $vulnerability->id(), 'accepted' => true],
            ['id' => $b->id(), 'accepted' => true],
            ['id' => $c->id(), 'accepted' => true],
        ]);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of($batchResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability, $b, $c], [], new NullCoverageRecorder());

        self::assertCount(3, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertTrue($result[1]->isReviewerValidated());
        self::assertTrue($result[2]->isReviewerValidated());
    }

    public function test_batch_mode_chunks_when_vulnerabilities_exceed_batch_size(): void
    {
        $vulns = [];
        for ($i = 0; $i < 7; ++$i) {
            $vulns[] = $this->makeVulnerabilityAt(\sprintf('src/V%d.php', $i));
        }

        $callIndex = 0;
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(3))
            ->method('complete')
            ->willReturnCallback(static function () use (&$callIndex): LLMResponse {
                ++$callIndex;

                return LLMResponse::of('[]', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 3,
            ),
        );

        $reviewerAgent->review($vulns, [], new NullCoverageRecorder());

        self::assertSame(3, $callIndex);
    }

    public function test_batch_mode_rejects_vulnerabilities_missing_from_response(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        $batchResponse = (string) json_encode([
            ['id' => $vulnerability->id(), 'accepted' => true],
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($batchResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability, $b], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
    }

    public function test_batch_mode_records_coverage_per_finding(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        $batchResponse = (string) json_encode([
            ['id' => $vulnerability->id(), 'accepted' => true],
            ['id' => $b->id(), 'accepted' => false],
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($batchResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $reviewerAgent->review([$vulnerability, $b], [], $auditContext);

        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'rejected'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_batch_mode_marks_all_batch_vulnerabilities_errored_on_llm_exception(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new RuntimeException('API down'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability, $b], [], $auditContext);

        self::assertFalse($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_batch_mode_marks_all_batch_vulnerabilities_errored_on_json_parse_failure(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('not json{{{', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $reviewerAgent->review([$vulnerability, $b], [], $auditContext);

        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_batch_mode_rejects_all_when_response_is_empty(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 0)));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability, $b], [], $auditContext);

        self::assertFalse($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'rejected'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'rejected'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_batch_mode_preserves_results_from_first_batch_when_second_batch_is_processed(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');
        $c = $this->makeVulnerabilityAt('src/C.php');

        $batch1Response = (string) json_encode([
            ['id' => $vulnerability->id(), 'accepted' => true],
            ['id' => $b->id(), 'accepted' => true],
        ]);
        $batch2Response = (string) json_encode([
            ['id' => $c->id(), 'accepted' => true],
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturnOnConsecutiveCalls(
                LLMResponse::of($batch1Response, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)),
                LLMResponse::of($batch2Response, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)),
            );

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

        $result = $reviewerAgent->review([$vulnerability, $b, $c], [], new NullCoverageRecorder());

        self::assertCount(3, $result);
    }

    public function test_batch_mode_records_coverage_rejected_for_vulnerabilities_missing_from_response(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        $batchResponse = (string) json_encode([
            ['id' => $vulnerability->id(), 'accepted' => true],
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($batchResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $reviewerAgent->review([$vulnerability, $b], [], $auditContext);

        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'rejected'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_batch_mode_continues_processing_after_missing_response_entry(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        // Only second vuln is in response; first is missing
        $batchResponse = (string) json_encode([
            ['id' => $b->id(), 'accepted' => true],
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($batchResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability, $b], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertFalse($result[0]->isReviewerValidated());
        self::assertTrue($result[1]->isReviewerValidated());
    }

    public function test_batch_mode_skips_non_array_entries_in_response(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $b = $this->makeVulnerabilityAt('src/B.php');

        // Response mixes a scalar entry between valid array entries.
        // The scalar must be skipped without aborting batch processing.
        $batchResponse = (string) json_encode([
            ['id' => $vulnerability->id(), 'accepted' => true],
            'not an object',
            ['id' => $b->id(), 'accepted' => true],
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($batchResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability, $b], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertTrue($result[1]->isReviewerValidated());
    }

    public function test_batch_mode_logs_error_with_batch_size_and_error_context_on_json_exception(): void
    {
        $errorLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('error')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$errorLogs): void {
                $errorLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('info');
        $logger->method('debug');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('not json{{{', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $reviewerAgent->review(
            [$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')],
            [],
            new NullCoverageRecorder(),
        );

        $batchParseLogs = array_values(array_filter(
            $errorLogs,
            static fn (array $entry): bool => 'Failed to parse reviewer batch response' === $entry[0],
        ));

        self::assertCount(1, $batchParseLogs);
        self::assertSame(2, $batchParseLogs[0][1]['batch_size']);
        self::assertArrayHasKey('error', $batchParseLogs[0][1]);
        self::assertNotSame('', $batchParseLogs[0][1]['error']);
        self::assertSame('not json{{{', $batchParseLogs[0][1]['content_preview']);
    }

    public function test_batch_mode_logs_error_with_batch_size_and_error_context_on_llm_exception(): void
    {
        $errorLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('error')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$errorLogs): void {
                $errorLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('info');
        $logger->method('debug');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new RuntimeException('API down'));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $reviewerAgent->review(
            [$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')],
            [],
            new NullCoverageRecorder(),
        );

        $batchExLogs = array_values(array_filter(
            $errorLogs,
            static fn (array $entry): bool => 'Reviewer batch LLM call failed' === $entry[0],
        ));

        self::assertCount(1, $batchExLogs);
        self::assertSame(2, $batchExLogs[0][1]['batch_size']);
        self::assertArrayHasKey('error', $batchExLogs[0][1]);
        self::assertNotSame('', $batchExLogs[0][1]['error']);
    }

    public function test_batch_mode_applies_adjusted_severity_when_reviewer_elevates(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php', VulnerabilitySeverity::MEDIUM);

        $batchResponse = (string) json_encode([
            ['id' => $vulnerability->id(), 'accepted' => true, 'adjusted_severity' => 'critical'],
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($batchResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[0]->severity());
    }

    public function test_it_corrects_type_when_reviewer_reclassifies_accepted_finding(): void
    {
        // Attacker labelled it SQLi but reviewer determines it's actually an SSRF.
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Mislabelled finding', 0.9),
            new CodeLocation('src/Service/Webhook.php', 10, 12),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            'code',
        );

        $reviewResponse = (string) json_encode([
            'id' => $vulnerability->id(),
            'accepted' => true,
            'corrected_type' => 'ssrf',
            'reviewer_notes' => 'attacker mislabelled — this is SSRF, not SQLi',
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(VulnerabilityType::SSRF, $result[0]->type());
    }

    public function test_it_keeps_original_type_when_corrected_type_is_invalid_string(): void
    {
        $vulnerability = $this->makeVulnerability();

        $reviewResponse = (string) json_encode([
            'id' => $vulnerability->id(),
            'accepted' => true,
            'corrected_type' => 'NOT_A_REAL_TYPE',
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        // Original type survives a bad correction; accepted state is still honored.
        self::assertSame($vulnerability->type(), $result[0]->type());
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_it_ignores_corrected_type_when_finding_is_rejected(): void
    {
        $vulnerability = $this->makeVulnerability();

        $reviewResponse = (string) json_encode([
            'id' => $vulnerability->id(),
            'accepted' => false,
            'corrected_type' => 'ssrf',
        ]);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of($reviewResponse, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 100)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertFalse($result[0]->isReviewerValidated());
        self::assertSame($vulnerability->type(), $result[0]->type());
    }

    public function test_it_logs_debug_invalid_corrected_type_with_exact_context(): void
    {
        $vulnerability = $this->makeVulnerability();
        $debugLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true, 'corrected_type' => 'NOT_A_TYPE_999']), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        $invalidLogs = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => str_contains($entry[0], 'invalid corrected_type'),
        ));
        self::assertNotEmpty($invalidLogs);
        self::assertSame(['corrected_type' => 'NOT_A_TYPE_999'], $invalidLogs[0][1]);
    }

    public function test_it_ignores_corrected_type_when_value_is_not_a_string(): void
    {
        // Non-string corrected_type (e.g. integer) must be ignored — would TypeError on enum::from()
        // if the is_string guard were removed.
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true, 'corrected_type' => 12345]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame($vulnerability->type(), $result[0]->type());
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_it_records_coverage_validated_when_reviewer_accepts_finding(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent->review([$vulnerability], [], $auditContext);

        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/Controller/UserController.php', 'status' => 'validated']],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_rejected_when_reviewer_rejects_finding(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => false]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent->review([$vulnerability], [], $auditContext);

        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/Controller/UserController.php', 'status' => 'rejected']],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_rejected_when_reviewer_returns_empty_response(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 0)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent->review([$vulnerability], [], $auditContext);

        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/Controller/UserController.php', 'status' => 'rejected']],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_errored_on_reviewer_json_parse_failure(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willReturn(LLMResponse::of('garbage{{{', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent->review([$vulnerability], [], $auditContext);

        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/Controller/UserController.php', 'status' => 'errored']],
            $auditContext->coverage(),
        );
    }

    public function test_it_records_coverage_errored_on_reviewer_llm_exception(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new RuntimeException('API down'));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent->review([$vulnerability], [], $auditContext);

        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/Controller/UserController.php', 'status' => 'errored']],
            $auditContext->coverage(),
        );
    }

    public function test_single_review_propagates_llm_provider_exception_instead_of_swallowing_it(): void
    {
        $vulnerability = $this->makeVulnerability();
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new LLMProviderException('platform unreachable'));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $this->expectException(LLMProviderException::class);
        $this->expectExceptionMessage('platform unreachable');

        $reviewerAgent->review([$vulnerability], [], AuditContext::forProject($this->tmpDir));
    }

    public function test_single_review_propagates_budget_exceeded_exception_instead_of_swallowing_it(): void
    {
        $vulnerability = $this->makeVulnerability();
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(BudgetExceededException::forTokens(500, 100));
        $reviewerAgent = $this->makeReviewerAgent($llmClient);

        $this->expectException(BudgetExceededException::class);

        $reviewerAgent->review([$vulnerability], [], AuditContext::forProject($this->tmpDir));
    }

    public function test_batch_review_propagates_llm_provider_exception_instead_of_swallowing_it(): void
    {
        $batch = [$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(new LLMProviderException('platform unreachable'));
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $this->expectException(LLMProviderException::class);
        $this->expectExceptionMessage('platform unreachable');

        $reviewerAgent->review($batch, [], AuditContext::forProject($this->tmpDir));
    }

    public function test_batch_review_propagates_budget_exceeded_exception_instead_of_swallowing_it(): void
    {
        $batch = [$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient
            ->method('complete')
            ->willThrowException(BudgetExceededException::forTokens(500, 100));
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $this->expectException(BudgetExceededException::class);

        $reviewerAgent->review($batch, [], AuditContext::forProject($this->tmpDir));
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/reviewer_agent_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_it_reviews_singles_concurrently_when_batch_capable_and_concurrency_configured(): void
    {
        $vulnerabilities = [$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')];

        $llmClient = new class implements BatchCapableLLMClientInterface {
            public int $batchCalls = 0;

            public int $completeCalls = 0;

            public function complete(string $systemPrompt, string $userMessage): LLMResponse
            {
                ++$this->completeCalls;

                return LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(0, 0));
            }

            public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
            {
                return LLMResponse::of('{}', 'm', 'end_turn', TokenUsageSnapshot::of(0, 0));
            }

            public function model(): string
            {
                return 'm';
            }

            public function completeBatch(array $requests, int $maxConcurrent): array
            {
                ++$this->batchCalls;

                return array_map(
                    static fn (): LLMResponse => LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(0, 0)),
                    $requests,
                );
            }
        };

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
            ),
        );

        $reviewed = $reviewerAgent->review($vulnerabilities, [], new NullCoverageRecorder());

        self::assertSame(1, $llmClient->batchCalls);
        self::assertSame(0, $llmClient->completeCalls);
        self::assertCount(2, $reviewed);
        self::assertTrue($reviewed[0]->isReviewerValidated());
        self::assertTrue($reviewed[1]->isReviewerValidated());
    }

    public function test_concurrent_review_skips_the_batch_call_when_every_finding_is_a_cache_hit(): void
    {
        $vulnerabilities = [$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')];

        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatch');
        $llmClient->expects(self::never())->method('complete');

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(['accepted' => true]);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
            ),
        );

        $reviewed = $reviewerAgent->review($vulnerabilities, [], new NullCoverageRecorder());

        self::assertCount(2, $reviewed);
        self::assertTrue($reviewed[0]->isReviewerValidated());
        self::assertTrue($reviewed[1]->isReviewerValidated());
    }

    public function test_batch_json_mode_invokes_the_tool_aware_completion_when_tools_are_enabled(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient->expects(self::once())
            ->method('completeWithTools')
            ->willReturn(LLMResponse::of((string) json_encode([['id' => $vulnerability->id(), 'accepted' => true]]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn($toolRegistry);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
                toolsEnabled: true,
                useStructuredCollection: false,
            ),
            toolRegistryFactory: $toolFactory,
        );

        $reviewed = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $reviewed);
        self::assertTrue($reviewed[0]->isReviewerValidated());
    }

    public function test_it_stays_sequential_when_max_concurrent_is_one_even_if_batch_capable(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = new class implements BatchCapableLLMClientInterface {
            public int $batchCalls = 0;

            public int $completeCalls = 0;

            public function complete(string $systemPrompt, string $userMessage): LLMResponse
            {
                ++$this->completeCalls;

                return LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(0, 0));
            }

            public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
            {
                return LLMResponse::of('{}', 'm', 'end_turn', TokenUsageSnapshot::of(0, 0));
            }

            public function model(): string
            {
                return 'm';
            }

            public function completeBatch(array $requests, int $maxConcurrent): array
            {
                ++$this->batchCalls;

                return [];
            }
        };

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 1,
            ),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(0, $llmClient->batchCalls);
        self::assertSame(1, $llmClient->completeCalls);
    }

    public function test_it_uses_tool_registry_when_tools_enabled_and_factory_provided(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient->expects(self::once())
            ->method('completeWithTools')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn($toolRegistry);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                toolsEnabled: true,
            ),
            toolRegistryFactory: $toolFactory,
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());
    }

    public function test_it_falls_back_to_complete_when_tools_disabled(): void
    {
        $vulnerability = $this->makeVulnerability();

        $llmClient = self::createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn($toolRegistry);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                toolsEnabled: false,
            ),
            toolRegistryFactory: $toolFactory,
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());
    }

    public function test_tools_enabled_logs_when_factory_provided(): void
    {
        $vulnerability = $this->makeVulnerability();
        $infoLogs = [];

        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::of((string) json_encode(['accepted' => true]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10)));

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn($toolRegistry);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
            ),
            new ReviewerModeConfiguration(
                toolsEnabled: true,
            ),
            toolRegistryFactory: $toolFactory,
        );
        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(['Reviewer agent validating findings', ['count' => 1, 'batch_size' => 1, 'tools_enabled' => true, 'structured_collection' => false]], $infoLogs[0]);
    }

    private function makeReviewerAgent(LLMClientInterface $llmClient): ReviewerAgent
    {
        return new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(),
        );
    }

    public function test_structured_collection_validates_a_finding_via_a_record_review_tool_call(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                self::assertTrue($toolRegistry->has('record_review'));
                $toolRegistry->execute('record_review', [
                    'id' => $vulnerability->id(),
                    'accepted' => true,
                    'adjusted_severity' => 'critical',
                    'reviewer_notes' => 'confirmed',
                ]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
            });

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

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[0]->severity());
    }

    public function test_structured_collection_rejects_a_finding_when_no_verdict_is_recorded(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0)));

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

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_rejects_a_finding_when_the_llm_call_fails(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new RuntimeException('transport hiccup'));

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

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_batch_rekeys_verdicts_by_id(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/Accepted.php');
        $rejected = $this->makeVulnerabilityAt('src/Rejected.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability, $rejected): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $rejected->id(), 'accepted' => false]);
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
            });

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

        $result = $reviewerAgent->review([$vulnerability, $rejected], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
    }

    public function test_structured_concurrency_falls_back_to_json_when_the_client_cannot_batch_tools(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('completeBatch')
            ->willReturn([LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(0, 0))]);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_tools_opt_in_takes_precedence_over_structured_collection(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
                self::assertFalse($toolRegistry->has('record_review'));

                return LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(0, 0));
            });

        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn(new ToolRegistry([], new NullLogger()));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                toolsEnabled: true,
                useStructuredCollection: true,
            ),
            toolRegistryFactory: $toolFactory,
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_is_the_default_when_a_record_review_factory_is_wired(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                self::assertTrue($toolRegistry->has('record_review'));
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
            });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_flag_without_factory_falls_back_to_json_path(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_single_path_returns_a_verdict_for_every_finding(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/First.php');
        $second = $this->makeVulnerabilityAt('src/Second.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability, $second): LLMResponse {
                $id = str_contains($user, 'src/First.php') ? $vulnerability->id() : $second->id();
                $toolRegistry->execute('record_review', ['id' => $id, 'accepted' => true]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
            },
        );

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

        $result = $reviewerAgent->review([$vulnerability, $second], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertSame('src/First.php', $result[0]->filePath());
        self::assertSame('src/Second.php', $result[1]->filePath());
    }

    public function test_structured_collection_records_errored_coverage_and_returns_rejected_on_throwable(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new RuntimeException('transport hiccup'));

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

        $result = $reviewerAgent->review([$vulnerability], [], $auditContext);

        self::assertFalse($result[0]->isReviewerValidated());
        self::assertSame(
            [['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'errored']],
            $auditContext->coverage(),
        );
    }

    public function test_structured_collection_propagates_llm_provider_exception(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new NonTransientLLMFailureException('retired model'));

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

        $this->expectException(LLMProviderException::class);

        $reviewerAgent->review([$this->makeVulnerabilityAt('src/A.php')], [], new NullCoverageRecorder());
    }

    public function test_structured_collection_propagates_budget_exceeded_exception(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new BudgetExceededException('budget gone'));

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

        $this->expectException(BudgetExceededException::class);

        $reviewerAgent->review([$this->makeVulnerabilityAt('src/A.php')], [], new NullCoverageRecorder());
    }

    public function test_structured_collection_batch_marks_errored_on_throwable(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new RuntimeException('transport hiccup'));

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

        $result = $reviewerAgent->review([$this->makeVulnerabilityAt('src/A.php'), $this->makeVulnerabilityAt('src/B.php')], [], $auditContext);

        self::assertFalse($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/B.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    public function test_structured_collection_batch_propagates_llm_provider_exception(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new NonTransientLLMFailureException('retired model'));

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

        $this->expectException(LLMProviderException::class);

        $reviewerAgent->review([$this->makeVulnerabilityAt('src/A.php')], [], new NullCoverageRecorder());
    }

    public function test_structured_collection_batch_propagates_budget_exceeded_exception(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new BudgetExceededException('budget gone'));

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

        $this->expectException(BudgetExceededException::class);

        $reviewerAgent->review([$this->makeVulnerabilityAt('src/A.php')], [], new NullCoverageRecorder());
    }

    public function test_cache_hit_short_circuits_the_llm_call_and_applies_the_stored_verdict(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php', VulnerabilitySeverity::MEDIUM);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient->expects(self::never())->method('completeWithTools');

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(['accepted' => true, 'adjusted_severity' => 'critical']);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[0]->severity());
    }

    public function test_cache_hit_logs_debug_message_with_the_vulnerability_id(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php', VulnerabilitySeverity::MEDIUM);

        $llmClient = self::createStub(LLMClientInterface::class);

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(['accepted' => true]);

        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $message, array $context = []) use (&$debugLogs): void {
                $debugLogs[] = [$message, $context];
            },
        );

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        $cacheHitLogs = array_values(array_filter(
            $debugLogs,
            static fn (array $entry): bool => 'Reviewer verdict served from cache' === $entry[0],
        ));
        self::assertCount(1, $cacheHitLogs);
        self::assertSame(['vulnerability_id' => $vulnerability->id()], $cacheHitLogs[0][1]);
    }

    public function test_cache_miss_calls_the_llm_and_stores_the_parsed_verdict(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(
            LLMResponse::of((string) json_encode(['accepted' => true]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())
            ->method('store')
            ->with($vulnerability, '', ['accepted' => true]);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_bypass_cache_skips_both_get_and_store(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(
            LLMResponse::of((string) json_encode(['accepted' => true]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::never())->method('get');
        $reviewerCache->expects(self::never())->method('store');

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder(), bypassCache: true);

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_cache_miss_does_not_store_when_the_response_is_empty(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::never())->method('store');

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_cache_miss_does_not_log_a_cache_hit(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(
            LLMResponse::of((string) json_encode(['accepted' => true]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);

        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $message, array $context = []) use (&$debugLogs): void {
                $debugLogs[] = $message;
            },
        );

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                $logger,
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertNotContains('Reviewer verdict served from cache', $debugLogs);
    }

    public function test_structured_collection_opt_out_uses_the_json_path(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturn(LLMResponse::of((string) json_encode(['accepted' => true]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: false,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_cache_hit_short_circuits_the_llm_call(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php', VulnerabilitySeverity::MEDIUM);

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient->expects(self::never())->method('completeWithTools');

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(['accepted' => true, 'adjusted_severity' => 'critical']);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[0]->severity());
    }

    public function test_structured_collection_cache_miss_stores_the_recorded_verdict(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
            },
        );

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())
            ->method('store')
            ->with($vulnerability, '', ['id' => $vulnerability->id(), 'accepted' => true]);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_bypass_cache_skips_both_get_and_store(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
            },
        );

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::never())->method('get');
        $reviewerCache->expects(self::never())->method('store');

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder(), bypassCache: true);

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_collection_does_not_store_when_no_verdict_is_recorded(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(
            LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5)),
        );

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::never())->method('store');

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertFalse($result[0]->isReviewerValidated());
    }

    public function test_structured_reviews_run_concurrently_when_the_client_can_batch_tools(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/First.php');
        $second = $this->makeVulnerabilityAt('src/Second.php');

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient
            ->expects(self::once())
            ->method('completeBatchWithTools')
            ->willReturnCallback(
                static function (array $requests, int $maxConcurrent, int $maxToolIterations) use ($vulnerability, $second): array {
                    self::assertCount(2, $requests);
                    self::assertSame(4, $maxConcurrent);
                    self::registryOf($requests[0])->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);
                    self::registryOf($requests[1])->execute('record_review', ['id' => $second->id(), 'accepted' => false]);

                    return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
                });

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

        $result = $reviewerAgent->review([$vulnerability, $second], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertSame('src/First.php', $result[0]->filePath());
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertSame('src/Second.php', $result[1]->filePath());
        self::assertFalse($result[1]->isReviewerValidated());
    }

    public function test_concurrent_structured_path_logs_structured_collection_enabled(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->method('completeBatchWithTools')
            ->willReturnCallback(
                static function (array $requests) use ($vulnerability): array {
                    self::registryOf($requests[0])->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                    return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
                });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                $logger,
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
                useStructuredCollection: true,
            ),
        );

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(['Reviewer agent validating findings', ['count' => 1, 'batch_size' => 1, 'tools_enabled' => false, 'structured_collection' => true]], $infoLogs[0]);
    }

    public function test_structured_concurrent_reviews_serve_cached_verdicts_and_dispatch_only_misses(): void
    {
        $first = $this->makeVulnerabilityAt('src/First.php');
        $second = $this->makeVulnerabilityAt('src/Second.php');
        $third = $this->makeVulnerabilityAt('src/Third.php');

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturnOnConsecutiveCalls(null, ['accepted' => true], null);
        $storedFor = [];
        $reviewerCache->method('store')->willReturnCallback(
            static function (Vulnerability $vulnerability) use (&$storedFor): void {
                $storedFor[] = $vulnerability->filePath();
            },
        );

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeBatchWithTools')
            ->willReturnCallback(
                static function (array $requests) use ($first, $third): array {
                    self::assertCount(2, $requests);
                    self::registryOf($requests[0])->execute('record_review', ['id' => $first->id(), 'accepted' => true]);
                    self::registryOf($requests[1])->execute('record_review', ['id' => $third->id(), 'accepted' => true]);

                    return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
                });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$first, $second, $third], [], new NullCoverageRecorder());

        self::assertCount(3, $result);
        self::assertSame('src/First.php', $result[0]->filePath());
        self::assertSame('src/Second.php', $result[1]->filePath());
        self::assertSame('src/Third.php', $result[2]->filePath());
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertTrue($result[1]->isReviewerValidated());
        self::assertTrue($result[2]->isReviewerValidated());
        self::assertSame(['src/First.php', 'src/Third.php'], $storedFor);
    }

    public function test_structured_concurrent_bypass_cache_skips_both_get_and_store(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::never())->method('get');
        $reviewerCache->expects(self::never())->method('store');

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->method('completeBatchWithTools')
            ->willReturnCallback(
                static function (array $requests) use ($vulnerability): array {
                    self::registryOf($requests[0])->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                    return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
                });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder(), bypassCache: true);

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_concurrent_reviews_mark_pending_findings_errored_on_throwable(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $second = $this->makeVulnerabilityAt('src/B.php');

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willThrowException(new RuntimeException('boom'));

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

        $result = $reviewerAgent->review([$vulnerability, $second], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertSame('src/A.php', $result[0]->filePath());
        self::assertFalse($result[0]->isReviewerValidated());
        self::assertSame('src/B.php', $result[1]->filePath());
        self::assertFalse($result[1]->isReviewerValidated());
    }

    public function test_structured_concurrent_reviews_propagate_llm_provider_exceptions(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willThrowException(new LLMProviderException('platform gone'));

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

        $this->expectException(LLMProviderException::class);

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());
    }

    public function test_structured_concurrent_reviews_propagate_budget_exceeded(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willThrowException(BudgetExceededException::forTokens(10, 5));

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

        $this->expectException(BudgetExceededException::class);

        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());
    }

    public function test_concurrent_json_reviews_serve_cached_verdicts_and_dispatch_only_misses(): void
    {
        $first = $this->makeVulnerabilityAt('src/First.php');
        $second = $this->makeVulnerabilityAt('src/Second.php');
        $third = $this->makeVulnerabilityAt('src/Third.php');

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturnOnConsecutiveCalls(null, ['accepted' => true], null);
        $storedFor = [];
        $reviewerCache->method('store')->willReturnCallback(
            static function (Vulnerability $vulnerability) use (&$storedFor): void {
                $storedFor[] = $vulnerability->filePath();
            },
        );

        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('completeBatch')
            ->willReturnCallback(static function (array $requests): array {
                self::assertCount(2, $requests);

                return [
                    LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                    LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                ];
            });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
            ),
        );

        $result = $reviewerAgent->review([$first, $second, $third], [], new NullCoverageRecorder());

        self::assertCount(3, $result);
        self::assertSame('src/First.php', $result[0]->filePath());
        self::assertSame('src/Second.php', $result[1]->filePath());
        self::assertSame('src/Third.php', $result[2]->filePath());
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertTrue($result[1]->isReviewerValidated());
        self::assertTrue($result[2]->isReviewerValidated());
        self::assertSame(['src/First.php', 'src/Third.php'], $storedFor);
    }

    public function test_concurrent_json_reviews_bypass_cache_skips_both_get_and_store(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::never())->method('get');
        $reviewerCache->expects(self::never())->method('store');

        $llmClient = self::createStub(BatchCapableLLMClientInterface::class);
        $llmClient
            ->method('completeBatch')
            ->willReturn([LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))]);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder(), bypassCache: true);

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_batched_reviews_serve_cached_verdicts_and_batch_only_misses(): void
    {
        $first = $this->makeVulnerabilityAt('src/First.php');
        $second = $this->makeVulnerabilityAt('src/Second.php');
        $third = $this->makeVulnerabilityAt('src/Third.php');

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturnOnConsecutiveCalls(null, ['accepted' => true, 'adjusted_severity' => 'critical'], null);
        $storedFor = [];
        $reviewerCache->method('store')->willReturnCallback(
            static function (Vulnerability $vulnerability) use (&$storedFor): void {
                $storedFor[] = $vulnerability->filePath();
            },
        );

        $capturedUserMessage = null;
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient
            ->expects(self::once())
            ->method('complete')
            ->willReturnCallback(static function (string $system, string $user) use ($first, $third, &$capturedUserMessage): LLMResponse {
                $capturedUserMessage = $user;

                return LLMResponse::of((string) json_encode([
                    ['id' => $first->id(), 'accepted' => true],
                    ['id' => $third->id(), 'accepted' => true],
                ]), 'claude', 'end_turn', TokenUsageSnapshot::of(10, 10));
            });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$first, $second, $third], [], new NullCoverageRecorder());

        self::assertCount(3, $result);
        self::assertSame('src/First.php', $result[0]->filePath());
        self::assertSame('src/Second.php', $result[1]->filePath());
        self::assertSame('src/Third.php', $result[2]->filePath());
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertTrue($result[1]->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[1]->severity());
        self::assertTrue($result[2]->isReviewerValidated());
        self::assertStringContainsString('src/First.php', (string) $capturedUserMessage);
        self::assertStringContainsString('src/Third.php', (string) $capturedUserMessage);
        self::assertStringNotContainsString('src/Second.php', (string) $capturedUserMessage);
        self::assertSame(['src/First.php', 'src/Third.php'], $storedFor);
    }

    public function test_batched_review_cache_miss_stores_the_matched_verdict(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(
            LLMResponse::of((string) json_encode([['id' => $vulnerability->id(), 'accepted' => true]]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())
            ->method('store')
            ->with($vulnerability, '', ['id' => $vulnerability->id(), 'accepted' => true]);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_batched_review_bypass_cache_skips_both_get_and_store(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(
            LLMResponse::of((string) json_encode([['id' => $vulnerability->id(), 'accepted' => true]]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::never())->method('get');
        $reviewerCache->expects(self::never())->method('store');

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder(), bypassCache: true);

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_batched_review_cache_miss_does_not_store_an_unmatched_finding(): void
    {
        $matched = $this->makeVulnerabilityAt('src/Matched.php');
        $unmatched = $this->makeVulnerabilityAt('src/Unmatched.php');

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(
            LLMResponse::of((string) json_encode([['id' => $matched->id(), 'accepted' => true]]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $storedFor = [];
        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->method('store')->willReturnCallback(
            static function (Vulnerability $vulnerability) use (&$storedFor): void {
                $storedFor[] = $vulnerability->filePath();
            },
        );

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                reviewerCache: $reviewerCache,
            ),
            new ReviewerModeConfiguration(
                batchSize: 5,
            ),
        );

        $result = $reviewerAgent->review([$matched, $unmatched], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
        self::assertSame(['src/Matched.php'], $storedFor);
    }

    public function test_structured_reviews_stay_sequential_when_concurrency_is_not_requested(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatchWithTools');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

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

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
    }

    public function test_structured_batches_ignore_the_concurrency_opt_in(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');
        $second = $this->makeVulnerabilityAt('src/B.php');

        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability, $second): LLMResponse {
                self::assertTrue($toolRegistry->has('record_review'));
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);
                $toolRegistry->execute('record_review', ['id' => $second->id(), 'accepted' => true]);

                return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            });

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: true),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                batchSize: 2,
                maxConcurrent: 4,
                useStructuredCollection: true,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability, $second], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertTrue($result[1]->isReviewerValidated());
    }

    public function test_structured_opt_out_keeps_the_json_path_even_on_a_tool_batch_capable_client(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatchWithTools');
        $llmClient
            ->expects(self::once())
            ->method('completeBatch')
            ->willReturn([LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))]);

        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(),
                new NullLogger(),
                recordReviewToolFactory: new RecordReviewToolFactory(),
            ),
            new ReviewerModeConfiguration(
                maxConcurrent: 4,
                useStructuredCollection: false,
            ),
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertTrue($result[0]->isReviewerValidated());
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        self::assertIsArray($request);
        $toolRegistry = $request['tools'] ?? null;
        self::assertInstanceOf(ToolRegistry::class, $toolRegistry);

        return $toolRegistry;
    }

    private function makeVulnerabilityAt(
        string $filePath,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
    ): Vulnerability {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::BROKEN_ACCESS_CONTROL, $vulnerabilitySeverity, 'Test '.$filePath, 0.9),
            new CodeLocation($filePath, 1, 5),
            new VulnerabilityNarrative('Test', 'vec', 'proof', 'fix'),
            'code',
        );
    }

    private function makeVulnerability(
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
    ): Vulnerability {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::BROKEN_ACCESS_CONTROL, $vulnerabilitySeverity, 'Missing access control', 0.9),
            new CodeLocation('src/Controller/UserController.php', 10, 20),
            new VulnerabilityNarrative('No voter on admin route', 'Direct access', 'GET /admin/user/1/edit', 'Add IsGranted'),
            'public function editUser()',
        );
    }

    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php class UserController {}');
    }
}
