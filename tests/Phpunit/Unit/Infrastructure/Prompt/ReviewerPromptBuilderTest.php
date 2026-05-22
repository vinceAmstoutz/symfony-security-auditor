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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class ReviewerPromptBuilderTest extends TestCase
{
    private ReviewerPromptBuilder $reviewerPromptBuilder;

    protected function setUp(): void
    {
        $this->reviewerPromptBuilder = new ReviewerPromptBuilder();
    }

    public function test_batch_system_prompt_instructs_to_return_array_one_per_input(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString('JSON array', $prompt);
        self::assertStringContainsString('one entry per input vulnerability', $prompt);
    }

    public function test_batch_user_message_starts_with_reports_header(): void
    {
        $vulnerabilities = [$this->makeVulnerability('src/A.php')];

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage(
            $vulnerabilities,
            [$vulnerabilities[0]->id() => 'code'],
        );

        self::assertStringStartsWith('## Vulnerability Reports to Review', $message);
    }

    public function test_batch_user_message_numbers_findings_starting_from_one(): void
    {
        $vulnerabilities = [
            $this->makeVulnerability('src/A.php'),
            $this->makeVulnerability('src/B.php'),
        ];

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage($vulnerabilities, []);

        self::assertStringContainsString('### Finding 1', $message);
        self::assertStringContainsString('### Finding 2', $message);
        self::assertStringNotContainsString('### Finding 0', $message);
        self::assertStringNotContainsString('### Finding 3', $message);
    }

    public function test_batch_user_message_finding_numbers_match_input_position(): void
    {
        $vulnerabilities = [
            $this->makeVulnerability('src/A.php'),
            $this->makeVulnerability('src/B.php'),
        ];

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage($vulnerabilities, []);

        // Finding 1 must reference src/A.php; Finding 2 must reference src/B.php
        $finding1Pos = strpos($message, '### Finding 1');
        $finding2Pos = strpos($message, '### Finding 2');
        $aPos = strpos($message, 'src/A.php');
        $bPos = strpos($message, 'src/B.php');

        self::assertNotFalse($finding1Pos);
        self::assertNotFalse($finding2Pos);
        self::assertNotFalse($aPos);
        self::assertNotFalse($bPos);
        self::assertLessThan($finding2Pos, $finding1Pos);
        self::assertLessThan($finding2Pos, $aPos);
        self::assertGreaterThan($finding2Pos, $bPos);
    }

    public function test_batch_user_message_ends_with_trailing_array_instruction(): void
    {
        $vulnerabilities = [$this->makeVulnerability('src/A.php')];

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage($vulnerabilities, []);

        self::assertStringEndsWith('Return a JSON array of reviews, one per finding above, in the same order.', $message);
    }

    public function test_batch_user_message_includes_code_context_for_finding_id(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $context = '<?php echo "sensitive-marker-token";';

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage(
            [$vulnerability],
            [$vulnerability->id() => $context],
        );

        self::assertStringContainsString('sensitive-marker-token', $message);
    }

    public function test_batch_user_message_uses_empty_string_when_code_context_missing_for_id(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage([$vulnerability], []);

        // Should still produce output without throwing; the code section will be empty
        self::assertStringContainsString('### Finding 1', $message);
    }

    private function makeVulnerability(string $filePath): Vulnerability
    {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Title for '.$filePath,
            description: 'Desc',
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
}
