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
use RuntimeException;
use Symfony\Component\ErrorHandler\BufferingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\PoCSynthesizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

final class PoCSynthesizerTest extends TestCase
{
    public function test_it_returns_empty_when_input_is_empty(): void
    {
        $llmClient = self::createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger());

        self::assertSame([], $poCSynthesizer->synthesize([]));
    }

    public function test_it_synthesizes_poc_for_validated_high_severity_finding(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::create(
            "```sh\ncurl -X POST /admin/users\n```",
            10, 10, 'claude', 'end_turn',
        ));

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger());

        $enriched = $poCSynthesizer->synthesize([$vulnerability]);

        self::assertNotNull($enriched[0]->synthesizedPoC());
        self::assertStringContainsString('curl -X POST /admin/users', (string) $enriched[0]->synthesizedPoC());
    }

    public function test_it_skips_findings_below_severity_floor(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::LOW)->withReviewerValidation(true);

        $llmClient = self::createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger(), VulnerabilitySeverity::HIGH);

        $enriched = $poCSynthesizer->synthesize([$vulnerability]);

        self::assertNull($enriched[0]->synthesizedPoC());
    }

    public function test_it_skips_findings_not_validated_by_reviewer(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH);

        $llmClient = self::createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger());

        $enriched = $poCSynthesizer->synthesize([$vulnerability]);

        self::assertNull($enriched[0]->synthesizedPoC());
    }

    public function test_it_keeps_original_when_llm_returns_empty(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::create('', 0, 0, 'test', 'end_turn'));

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger());

        $enriched = $poCSynthesizer->synthesize([$vulnerability]);

        self::assertNull($enriched[0]->synthesizedPoC());
    }

    public function test_it_keeps_original_when_llm_throws_generic_exception(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new RuntimeException('network'));

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger());

        $enriched = $poCSynthesizer->synthesize([$vulnerability]);

        self::assertNull($enriched[0]->synthesizedPoC());
    }

    public function test_severity_floor_medium_includes_medium_findings(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::MEDIUM)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::create(
            'curl /x',
            10, 10, 'claude', 'end_turn',
        ));

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger(), VulnerabilitySeverity::MEDIUM);

        $enriched = $poCSynthesizer->synthesize([$vulnerability]);

        self::assertNotNull($enriched[0]->synthesizedPoC());
    }

    public function test_returned_list_preserves_input_order_and_length(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH, filePath: 'src/A.php')->withReviewerValidation(true);
        $b = $this->makeVulnerability(VulnerabilitySeverity::LOW, filePath: 'src/B.php')->withReviewerValidation(true);
        $c = $this->makeVulnerability(VulnerabilitySeverity::CRITICAL, filePath: 'src/C.php')->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::create('PoC', 0, 0, 'test', 'end_turn'));

        $poCSynthesizer = new PoCSynthesizer($llmClient, new NullLogger());

        $enriched = $poCSynthesizer->synthesize([$vulnerability, $b, $c]);

        self::assertCount(3, $enriched);
        self::assertSame('src/A.php', $enriched[0]->filePath());
        self::assertSame('src/B.php', $enriched[1]->filePath());
        self::assertSame('src/C.php', $enriched[2]->filePath());
        self::assertNotNull($enriched[0]->synthesizedPoC());
        self::assertNull($enriched[1]->synthesizedPoC());
        self::assertNotNull($enriched[2]->synthesizedPoC());
    }

    public function test_it_logs_completion_summary_with_inputs_synthesized_and_skipped_counts(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $belowFloor = $this->makeVulnerability(VulnerabilitySeverity::LOW)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::create('curl /x', 10, 10, 'claude', 'end_turn'));

        $bufferingLogger = new BufferingLogger();
        (new PoCSynthesizer($llmClient, $bufferingLogger))->synthesize([$vulnerability, $belowFloor]);

        $logs = $bufferingLogger->cleanLogs();
        $completion = end($logs);
        self::assertSame('PoC synthesis complete', $completion[1]);
        self::assertSame(['inputs' => 2, 'synthesized' => 1, 'skipped' => 1], $completion[2]);
    }

    public function test_it_does_not_log_completion_for_empty_input(): void
    {
        $bufferingLogger = new BufferingLogger();

        (new PoCSynthesizer(self::createStub(LLMClientInterface::class), $bufferingLogger))->synthesize([]);

        self::assertSame([], $bufferingLogger->cleanLogs());
    }

    public function test_it_logs_vulnerability_id_and_error_when_synthesis_throws(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new RuntimeException('network down'));

        $bufferingLogger = new BufferingLogger();
        (new PoCSynthesizer($llmClient, $bufferingLogger))->synthesize([$vulnerability]);

        $logs = $bufferingLogger->cleanLogs();
        self::assertSame('error', $logs[0][0]);
        self::assertSame('PoC synthesis call failed; keeping original proof', $logs[0][1]);
        self::assertSame($vulnerability->id(), $logs[0][2]['vulnerability_id']);
        self::assertSame('network down', $logs[0][2]['error']);
    }

    public function test_it_rethrows_budget_exceeded_exception(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(BudgetExceededException::forCost(2.0, 1.0));

        $this->expectException(BudgetExceededException::class);
        (new PoCSynthesizer($llmClient, new NullLogger()))->synthesize([$vulnerability]);
    }

    public function test_it_rethrows_llm_provider_exception(): void
    {
        $vulnerability = $this->makeVulnerability(VulnerabilitySeverity::HIGH)->withReviewerValidation(true);

        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new LLMProviderException('retired model'));

        $this->expectException(LLMProviderException::class);
        (new PoCSynthesizer($llmClient, new NullLogger()))->synthesize([$vulnerability]);
    }

    private function makeVulnerability(
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
        string $filePath = 'src/Controller/Foo.php',
    ): Vulnerability {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: $vulnerabilitySeverity,
            title: 'Test',
            description: 'd',
            filePath: $filePath,
            lineStart: 10,
            lineEnd: 15,
            vulnerableCode: 'code',
            attackVector: 'av',
            proof: 'proof',
            remediation: 'r',
            confidence: 0.9,
        );
    }
}
