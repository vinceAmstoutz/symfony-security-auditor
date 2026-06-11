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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create('not json!!!', 100, 10, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create('', 100, 0, 'claude', 'end_turn'));
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
                LLMResponse::create(
                    (string) json_encode(['accepted' => true, 'reviewer_notes' => 'confirmed']),
                    100, 100, 'claude', 'end_turn',
                ),
                LLMResponse::create(
                    (string) json_encode(['accepted' => false, 'reviewer_notes' => 'false positive']),
                    100, 100, 'claude', 'end_turn',
                ),
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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

                return LLMResponse::create(
                    (string) json_encode(['accepted' => false]),
                    100, 10, 'claude', 'end_turn',
                );
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

                return LLMResponse::create(
                    (string) json_encode(['accepted' => false, 'reviewer_notes' => 'ok']),
                    100,
                    10,
                    'claude',
                    'end_turn',
                );
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true]),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create('invalid json {{{', 10, 10, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create($longInvalidContent, 0, 0, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create($longInvalidContent, 0, 0, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
            batchSize: 5,
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
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true, 'reviewer_notes' => 'confirmed']),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => false, 'reviewer_notes' => 'rejected']),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true, 'reviewer_notes' => 'looks good']),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create('', 10, 0, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true, 'adjusted_severity' => 'SUPER_CRITICAL_9000']),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['reviewer_notes' => 'no accepted key']),
                10, 10, 'claude', 'end_turn',
            ));
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => false, 'reviewer_notes' => 'false positive']),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode([
                    'accepted' => true,
                    'adjusted_severity' => 'critical',
                    'reviewer_notes' => 'severity upgraded',
                ]),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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

                    return LLMResponse::create(
                        (string) json_encode(['accepted' => true]),
                        10, 10, 'claude', 'end_turn',
                    );
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
            ->willReturn(LLMResponse::create($batchResponse, 10, 10, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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

                return LLMResponse::create('[]', 0, 0, 'claude', 'end_turn');
            });

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 3,
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
            ->willReturn(LLMResponse::create($batchResponse, 10, 10, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            ->willReturn(LLMResponse::create($batchResponse, 10, 10, 'claude', 'end_turn'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            ->willReturn(LLMResponse::create('not json{{{', 10, 10, 'claude', 'end_turn'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            ->willReturn(LLMResponse::create('', 10, 0, 'claude', 'end_turn'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
                LLMResponse::create($batch1Response, 0, 0, 'claude', 'end_turn'),
                LLMResponse::create($batch2Response, 0, 0, 'claude', 'end_turn'),
            );

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 2,
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
            ->willReturn(LLMResponse::create($batchResponse, 0, 0, 'claude', 'end_turn'));

        $auditContext = AuditContext::forProject($this->tmpDir);

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            ->willReturn(LLMResponse::create($batchResponse, 0, 0, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            ->willReturn(LLMResponse::create($batchResponse, 0, 0, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            ->willReturn(LLMResponse::create('not json{{{', 0, 0, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
            batchSize: 5,
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
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
            batchSize: 5,
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
            ->willReturn(LLMResponse::create($batchResponse, 10, 10, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(VulnerabilitySeverity::CRITICAL, $result[0]->severity());
    }

    public function test_it_corrects_type_when_reviewer_reclassifies_accepted_finding(): void
    {
        // Attacker labelled it SQLi but reviewer determines it's actually an SSRF.
        $vulnerability = Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Mislabelled finding',
            description: 'desc',
            filePath: 'src/Service/Webhook.php',
            lineStart: 10,
            lineEnd: 12,
            vulnerableCode: 'code',
            attackVector: 'vec',
            proof: 'proof',
            remediation: 'fix',
            confidence: 0.9,
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create($reviewResponse, 100, 100, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true, 'corrected_type' => 'NOT_A_TYPE_999']),
                10, 10, 'claude', 'end_turn',
            ));

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true, 'corrected_type' => 12345]),
                10, 10, 'claude', 'end_turn',
            ));
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
            ->willReturn(LLMResponse::create((string) json_encode(['accepted' => true]), 10, 10, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create((string) json_encode(['accepted' => false]), 10, 10, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create('', 10, 0, 'claude', 'end_turn'));
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
            ->willReturn(LLMResponse::create('garbage{{{', 10, 10, 'claude', 'end_turn'));
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
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            batchSize: 5,
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

                return LLMResponse::create('{"accepted": true}', 0, 0, 'm', 'end_turn');
            }

            public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
            {
                return LLMResponse::create('{}', 0, 0, 'm', 'end_turn');
            }

            public function model(): string
            {
                return 'm';
            }

            public function completeBatch(array $requests, int $maxConcurrent): array
            {
                ++$this->batchCalls;

                return array_map(
                    static fn (): LLMResponse => LLMResponse::create('{"accepted": true}', 0, 0, 'm', 'end_turn'),
                    $requests,
                );
            }
        };

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            maxConcurrent: 4,
        );

        $reviewed = $reviewerAgent->review($vulnerabilities, [], new NullCoverageRecorder());

        self::assertSame(1, $llmClient->batchCalls);
        self::assertSame(0, $llmClient->completeCalls);
        self::assertCount(2, $reviewed);
        self::assertTrue($reviewed[0]->isReviewerValidated());
        self::assertTrue($reviewed[1]->isReviewerValidated());
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

                return LLMResponse::create('{"accepted": true}', 0, 0, 'm', 'end_turn');
            }

            public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
            {
                return LLMResponse::create('{}', 0, 0, 'm', 'end_turn');
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
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            maxConcurrent: 1,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true]),
                10, 10, 'claude', 'end_turn',
            ));

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn($toolRegistry);

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            toolRegistryFactory: $toolFactory,
            toolsEnabled: true,
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
            ->willReturn(LLMResponse::create(
                (string) json_encode(['accepted' => true]),
                10, 10, 'claude', 'end_turn',
            ));

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn($toolRegistry);

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
            toolRegistryFactory: $toolFactory,
            toolsEnabled: false,
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
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::create(
            (string) json_encode(['accepted' => true]),
            10, 10, 'claude', 'end_turn',
        ));

        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn($toolRegistry);

        $reviewerAgent = new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: $logger,
            toolRegistryFactory: $toolFactory,
            toolsEnabled: true,
        );
        $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertSame(['Reviewer agent validating findings', ['count' => 1, 'batch_size' => 1, 'tools_enabled' => true, 'structured_collection' => false]], $infoLogs[0]);
    }

    private function makeReviewerAgent(LLMClientInterface $llmClient): ReviewerAgent
    {
        return new ReviewerAgent(
            llmClient: $llmClient,
            reviewerPromptBuilder: new ReviewerPromptBuilder(),
            logger: new NullLogger(),
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

                return LLMResponse::create('', 10, 5, 'claude', 'end_turn');
            });

        $reviewerAgent = new ReviewerAgent(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new NullLogger(),
            recordReviewToolFactory: new RecordReviewToolFactory(),
            useStructuredCollection: true,
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
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::create('', 0, 0, 'claude', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new NullLogger(),
            recordReviewToolFactory: new RecordReviewToolFactory(),
            useStructuredCollection: true,
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
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new NullLogger(),
            recordReviewToolFactory: new RecordReviewToolFactory(),
            useStructuredCollection: true,
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

                return LLMResponse::create('', 10, 5, 'claude', 'end_turn');
            });

        $reviewerAgent = new ReviewerAgent(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new NullLogger(),
            batchSize: 5,
            recordReviewToolFactory: new RecordReviewToolFactory(),
            useStructuredCollection: true,
        );

        $result = $reviewerAgent->review([$vulnerability, $rejected], [], new NullCoverageRecorder());

        self::assertCount(2, $result);
        self::assertTrue($result[0]->isReviewerValidated());
        self::assertFalse($result[1]->isReviewerValidated());
    }

    public function test_structured_collection_takes_precedence_over_the_concurrent_fast_path(): void
    {
        $vulnerability = $this->makeVulnerabilityAt('src/A.php');

        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatch');
        $llmClient
            ->expects(self::once())
            ->method('completeWithTools')
            ->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($vulnerability): LLMResponse {
                $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

                return LLMResponse::create('', 10, 5, 'claude', 'end_turn');
            });

        $reviewerAgent = new ReviewerAgent(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new NullLogger(),
            maxConcurrent: 4,
            recordReviewToolFactory: new RecordReviewToolFactory(),
            useStructuredCollection: true,
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
            ->willReturn(LLMResponse::create((string) json_encode(['accepted' => true]), 0, 0, 'test', 'end_turn'));

        $reviewerAgent = new ReviewerAgent(
            $llmClient,
            new ReviewerPromptBuilder(),
            new NullLogger(),
            useStructuredCollection: true,
        );

        $result = $reviewerAgent->review([$vulnerability], [], new NullCoverageRecorder());

        self::assertCount(1, $result);
        self::assertTrue($result[0]->isReviewerValidated());
    }

    private function makeVulnerabilityAt(
        string $filePath,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
    ): Vulnerability {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::BROKEN_ACCESS_CONTROL,
            vulnerabilitySeverity: $vulnerabilitySeverity,
            title: 'Test '.$filePath,
            description: 'Test',
            filePath: $filePath,
            lineStart: 1,
            lineEnd: 5,
            vulnerableCode: 'code',
            attackVector: 'vec',
            proof: 'proof',
            remediation: 'fix',
            confidence: 0.9,
        );
    }

    private function makeVulnerability(
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
    ): Vulnerability {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::BROKEN_ACCESS_CONTROL,
            vulnerabilitySeverity: $vulnerabilitySeverity,
            title: 'Missing access control',
            description: 'No voter on admin route',
            filePath: 'src/Controller/UserController.php',
            lineStart: 10,
            lineEnd: 20,
            vulnerableCode: 'public function editUser()',
            attackVector: 'Direct access',
            proof: 'GET /admin/user/1/edit',
            remediation: 'Add IsGranted',
            confidence: 0.9,
        );
    }

    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php class UserController {}');
    }
}
