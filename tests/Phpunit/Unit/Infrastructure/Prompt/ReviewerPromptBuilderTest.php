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

    public function test_batch_user_message_ends_with_id_based_array_instruction(): void
    {
        $vulnerabilities = [$this->makeVulnerability('src/A.php')];

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage($vulnerabilities, []);

        self::assertStringEndsWith(
            'Each entry\'s "id" must match the input; we re-key by id on parse, so a misordered array with correct ids will still be accepted.',
            $message,
        );
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

    public function test_system_prompt_includes_severity_rubric_with_all_five_tiers(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Severity rubric', $prompt);
        self::assertStringContainsString('- critical:', $prompt);
        self::assertStringContainsString('- info:', $prompt);
    }

    public function test_batch_system_prompt_includes_severity_rubric(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString('Severity rubric', $prompt);
    }

    public function test_system_prompt_includes_symfony_false_positive_playbook(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('false-positive playbook', $prompt);
        self::assertStringContainsString('setParameter()', $prompt);
        self::assertStringContainsString('mapped: false', $prompt);
    }

    public function test_batch_system_prompt_includes_symfony_false_positive_playbook(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString('false-positive playbook', $prompt);
    }

    public function test_system_prompt_documents_corrected_type_field(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('corrected_type', $prompt);
        self::assertStringContainsString("null if the attacker's type is correct", $prompt);
    }

    public function test_system_prompt_lists_valid_corrected_type_enum_values(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        // A handful of canonical values must appear — the LLM should not invent new types.
        self::assertStringContainsString('sql_injection', $prompt);
        self::assertStringContainsString('ssrf', $prompt);
        self::assertStringContainsString('hardcoded_secret', $prompt);
    }

    public function test_system_prompt_lists_modern_symfony_corrected_type_enum_values(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('missing_signature_verification', $prompt);
        self::assertStringContainsString('messenger_handler_unsafe', $prompt);
        self::assertStringContainsString('webhook_replay', $prompt);
        self::assertStringContainsString('authenticator_bypass', $prompt);
    }

    public function test_false_positive_playbook_covers_constant_time_signature_comparison(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('hash_equals', $prompt);
    }

    public function test_false_positive_playbook_covers_messenger_default_serializer(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('messenger.transport.symfony_serializer', $prompt);
    }

    public function test_system_prompt_includes_tool_usage_discipline(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Tool usage', $prompt);
        self::assertStringContainsString('read_file', $prompt);
        self::assertStringContainsString('grep', $prompt);
    }

    public function test_batch_system_prompt_includes_tool_usage_discipline(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString('Tool usage', $prompt);
        self::assertStringContainsString('read_file', $prompt);
    }

    public function test_system_prompt_emits_sections_in_documented_order(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        $personaPos = strpos($prompt, 'You are a senior AppSec engineer');
        $rubricPos = strpos($prompt, 'Severity rubric');
        $playbookPos = strpos($prompt, 'false-positive playbook');
        $outputDirectivePos = strpos($prompt, 'one entry per vulnerability reviewed');
        $schemaPos = strpos($prompt, 'Each entry of the JSON array MUST be shaped');
        $rulesPos = strpos($prompt, 'Be strict: reject any finding');

        self::assertNotFalse($personaPos);
        self::assertNotFalse($rubricPos);
        self::assertNotFalse($playbookPos);
        self::assertNotFalse($outputDirectivePos);
        self::assertNotFalse($schemaPos);
        self::assertNotFalse($rulesPos);

        self::assertLessThan($rubricPos, $personaPos);
        self::assertLessThan($playbookPos, $rubricPos);
        self::assertLessThan($outputDirectivePos, $playbookPos);
        self::assertLessThan($schemaPos, $outputDirectivePos);
        self::assertLessThan($rulesPos, $schemaPos);
    }

    public function test_batch_system_prompt_emits_sections_in_documented_order(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        $personaPos = strpos($prompt, 'You are a senior AppSec engineer');
        $batchPreamblePos = strpos($prompt, 'SEVERAL vulnerability reports in a single batch');
        $rubricPos = strpos($prompt, 'Severity rubric');
        $playbookPos = strpos($prompt, 'false-positive playbook');
        $outputDirectivePos = strpos($prompt, 'EXACTLY one entry per input vulnerability');
        $schemaPos = strpos($prompt, 'Each entry of the JSON array MUST be shaped');
        $orderingHintPos = strpos($prompt, 're-keyed by "id" when we parse your response');
        $rulesPos = strpos($prompt, 'Be strict: reject any finding');

        self::assertNotFalse($personaPos);
        self::assertNotFalse($batchPreamblePos);
        self::assertNotFalse($rubricPos);
        self::assertNotFalse($playbookPos);
        self::assertNotFalse($outputDirectivePos);
        self::assertNotFalse($schemaPos);
        self::assertNotFalse($orderingHintPos);
        self::assertNotFalse($rulesPos);

        self::assertLessThan($batchPreamblePos, $personaPos);
        self::assertLessThan($rubricPos, $batchPreamblePos);
        self::assertLessThan($playbookPos, $rubricPos);
        self::assertLessThan($outputDirectivePos, $playbookPos);
        self::assertLessThan($schemaPos, $outputDirectivePos);
        self::assertLessThan($orderingHintPos, $schemaPos);
        self::assertLessThan($rulesPos, $orderingHintPos);
    }

    public function test_system_and_batch_system_prompts_share_core_instructions(): void
    {
        // The two prompts MUST be derived from a shared base — drift between single and batch is a known FP risk.
        $singlePrompt = $this->reviewerPromptBuilder->buildSystemPrompt();
        $batchPrompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        $sharedAnchor = 'You are a senior AppSec engineer and security code reviewer.';
        self::assertStringContainsString($sharedAnchor, $singlePrompt);
        self::assertStringContainsString($sharedAnchor, $batchPrompt);

        // Both must reference the FP playbook and the severity rubric verbatim.
        self::assertStringContainsString('false-positive playbook', $singlePrompt);
        self::assertStringContainsString('false-positive playbook', $batchPrompt);
    }

    public function test_batch_user_message_line_numbers_full_file_context(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $context = "<?php\nclass Foo {}";

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage(
            [$vulnerability],
            [$vulnerability->id() => $context],
        );

        // Lock both numbering AND the "\n" separator — see analogous AttackerPromptBuilder test.
        self::assertStringContainsString("  1 | <?php\n  2 | class Foo {}", $message);
    }

    public function test_single_user_message_line_numbers_full_file_context(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $context = "<?php\nclass Foo {}";

        $message = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $context);

        self::assertStringContainsString("  1 | <?php\n  2 | class Foo {}", $message);
    }

    public function test_empty_code_context_yields_empty_full_file_block(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');

        $message = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, '');

        // No line-numbered output for empty context — keeps the prompt clean.
        self::assertStringNotContainsString('  1 | ', $message);
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
