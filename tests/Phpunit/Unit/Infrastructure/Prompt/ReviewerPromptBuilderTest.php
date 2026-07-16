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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class ReviewerPromptBuilderTest extends TestCase
{
    private ReviewerPromptBuilder $reviewerPromptBuilder;

    #[Override]
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_batch_user_message_starts_with_reports_header(): void
    {
        $vulnerabilities = [$this->makeVulnerability('src/A.php')];

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage(
            $vulnerabilities,
            [$vulnerabilities[0]->id() => 'code'],
        );

        self::assertStringStartsWith('## Vulnerability Reports to Review', $message);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_batch_user_message_ends_with_id_based_array_instruction(): void
    {
        $vulnerabilities = [$this->makeVulnerability('src/A.php')];

        $message = $this->reviewerPromptBuilder->buildBatchUserMessage($vulnerabilities, []);

        self::assertStringEndsWith(
            'Each entry\'s "id" must match the input; we re-key by id on parse, so a misordered array with correct ids will still be accepted.',
            $message,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
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
        self::assertStringContainsString('host_header_injection', $prompt);
        self::assertStringContainsString('trusted_proxy_misconfiguration', $prompt);
    }

    public function test_decision_rules_restrict_rejection_to_a_named_mitigating_control(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString(
            'Reject a finding ONLY when you can name a specific mitigating control',
            $prompt,
        );
        self::assertStringContainsString(
            '"Not clearly exploitable" is not, by itself, grounds to reject',
            $prompt,
        );
    }

    public function test_decision_rules_preserve_uncertain_findings_via_downgrade(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString(
            'do NOT reject: accept it and downgrade the severity',
            $prompt,
        );
        self::assertStringContainsString('state what evidence is missing in `reviewer_notes`', $prompt);
    }

    public function test_batch_decision_rules_restrict_rejection_to_a_named_mitigating_control(): void
    {
        $prompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString(
            'Reject a finding ONLY when you can name a specific mitigating control',
            $prompt,
        );
    }

    #[DataProvider('vulnerabilityTypeValues')]
    public function test_system_prompt_lists_every_vulnerability_type_as_corrected_type(string $typeValue): void
    {
        $prompt = $this->reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString($typeValue, $prompt);
    }

    #[DataProvider('vulnerabilityTypeValues')]
    public function test_batch_system_prompt_lists_every_vulnerability_type_as_corrected_type(string $typeValue): void
    {
        $prompt = $this->reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString($typeValue, $prompt);
    }

    /** @return iterable<string, array{string}> */
    public static function vulnerabilityTypeValues(): iterable
    {
        foreach (VulnerabilityType::cases() as $vulnerabilityType) {
            yield $vulnerabilityType->value => [$vulnerabilityType->value];
        }
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
        $rulesPos = strpos($prompt, 'Reject a finding ONLY when');

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
        $rulesPos = strpos($prompt, 'Reject a finding ONLY when');

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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_single_user_message_line_numbers_full_file_context(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $context = "<?php\nclass Foo {}";

        $message = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $context);

        self::assertStringContainsString("  1 | <?php\n  2 | class Foo {}", $message);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_empty_code_context_yields_empty_full_file_block(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');

        $message = $this->reviewerPromptBuilder->buildUserMessage($vulnerability, '');

        // No line-numbered output for empty context — keeps the prompt clean.
        self::assertStringNotContainsString('  1 | ', $message);
    }

    public function test_structured_system_prompt_directs_verdicts_through_record_review_tool(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder(useStructuredCollection: true);

        $prompt = $reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('`record_review` tool calls', $prompt);
        self::assertStringContainsString('EXACTLY one call per finding', $prompt);
        self::assertStringNotContainsString('Return ONLY the JSON array', $prompt);
        self::assertStringNotContainsString('Each entry of the JSON array MUST be shaped', $prompt);
    }

    public function test_structured_system_prompt_uses_the_same_lenient_decision_rules_as_the_default_mode(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder(useStructuredCollection: true);

        $prompt = $reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString(
            'Reject a finding ONLY when you can name a specific mitigating control',
            $prompt,
        );
        self::assertStringContainsString(
            '"Not clearly exploitable" is not, by itself, grounds to reject',
            $prompt,
        );
        self::assertStringContainsString(
            'do NOT reject: accept it and downgrade the severity',
            $prompt,
        );
        self::assertStringNotContainsString('Be strict: reject any finding', $prompt);
    }

    public function test_structured_system_prompt_keeps_rubric_and_playbook(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder(useStructuredCollection: true);

        $prompt = $reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('You are a senior AppSec engineer', $prompt);
        self::assertStringContainsString('Severity rubric', $prompt);
        self::assertStringContainsString('false-positive playbook', $prompt);
    }

    public function test_structured_batch_system_prompt_uses_the_same_lenient_decision_rules_as_the_default_mode(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder(useStructuredCollection: true);

        $prompt = $reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString(
            'Reject a finding ONLY when you can name a specific mitigating control',
            $prompt,
        );
        self::assertStringNotContainsString('Be strict: reject any finding', $prompt);
    }

    public function test_structured_batch_system_prompt_directs_one_record_review_call_per_input(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder(useStructuredCollection: true);

        $prompt = $reviewerPromptBuilder->buildBatchSystemPrompt();

        self::assertStringContainsString('You are a senior AppSec engineer', $prompt);
        self::assertStringContainsString('Record EXACTLY one review per input vulnerability via the `record_review` tool.', $prompt);
        self::assertStringContainsString('Verdicts are re-keyed by "id" when we collect your calls', $prompt);
        self::assertStringNotContainsString('Your output MUST be a JSON array', $prompt);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_single_user_message_asks_for_a_record_review_call(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder(useStructuredCollection: true);

        $message = $reviewerPromptBuilder->buildUserMessage($this->makeVulnerability('src/A.php'), 'code');

        self::assertStringContainsString('record your verdict via the `record_review` tool', $message);
        self::assertStringNotContainsString('return your review JSON', $message);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_structured_batch_user_message_asks_for_record_review_calls(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder(useStructuredCollection: true);
        $vulnerabilities = [$this->makeVulnerability('src/A.php')];

        $message = $reviewerPromptBuilder->buildBatchUserMessage($vulnerabilities, []);

        self::assertStringStartsWith('## Vulnerability Reports to Review', $message);
        self::assertStringEndsWith('Record one review per finding above via the `record_review` tool. Each call\'s "id" must match the input finding; we re-key by id when collecting your calls, so call order does not matter.', $message);
        self::assertStringNotContainsString('Return a JSON array of reviews', $message);
    }

    public function test_default_mode_keeps_the_json_array_contract(): void
    {
        $reviewerPromptBuilder = new ReviewerPromptBuilder();

        $prompt = $reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Return ONLY the JSON array', $prompt);
        self::assertStringNotContainsString('record_review', $prompt);
    }

    public function test_system_prompts_carry_no_feedback_section_without_baseline_feedback(): void
    {
        self::assertStringNotContainsString('Maintainer-accepted findings', (new ReviewerPromptBuilder())->buildSystemPrompt());
    }

    public function test_the_absent_feedback_section_leaves_no_blank_gap_between_prompt_sections(): void
    {
        self::assertStringNotContainsString("\n\n\n", (new ReviewerPromptBuilder())->buildSystemPrompt());
    }

    public function test_the_feedback_section_opens_with_the_maintainer_baseline_header(): void
    {
        $reviewerPromptBuilder = $this->builderWithFeedback(false, [
            new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', 'accepted risk'),
        ]);

        self::assertStringContainsString("Maintainer-accepted findings from this project's baseline (each with the maintainer's reason):", $reviewerPromptBuilder->buildSystemPrompt());
    }

    #[DataProvider('feedbackPromptVariants')]
    public function test_system_prompts_list_each_baseline_reason_as_a_negative_example(bool $useStructuredCollection, bool $batch): void
    {
        $reviewerPromptBuilder = $this->builderWithFeedback($useStructuredCollection, [
            new AcceptedFindingFeedback('sql_injection', 'src/Repository/A.php', 'Raw DQL', 'Goes through SafeQuery, parameterized upstream.'),
        ]);

        $prompt = $batch ? $reviewerPromptBuilder->buildBatchSystemPrompt() : $reviewerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('- [sql_injection] Raw DQL (src/Repository/A.php): Goes through SafeQuery, parameterized upstream.', $prompt);
    }

    /** @return iterable<string, array{bool, bool}> */
    public static function feedbackPromptVariants(): iterable
    {
        yield 'json single' => [false, false];
        yield 'json batch' => [false, true];
        yield 'structured single' => [true, false];
        yield 'structured batch' => [true, true];
    }

    public function test_the_feedback_section_warns_against_blind_rejection(): void
    {
        $reviewerPromptBuilder = $this->builderWithFeedback(false, [
            new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', 'accepted risk'),
        ]);

        self::assertStringContainsString('Never reject a finding solely because it resembles one of these', $reviewerPromptBuilder->buildSystemPrompt());
    }

    public function test_feedback_entries_beyond_the_prompt_cap_are_dropped(): void
    {
        $entries = [];
        for ($i = 1; $i <= ReviewerPromptBuilder::MAX_FEEDBACK_PROMPT_ENTRIES + 1; ++$i) {
            $entries[] = new AcceptedFindingFeedback('sql_injection', \sprintf('src/File%d.php', $i), \sprintf('Finding %d', $i), \sprintf('Reason %d', $i));
        }

        $prompt = $this->builderWithFeedback(false, $entries)->buildSystemPrompt();

        self::assertStringContainsString(\sprintf('Reason %d', ReviewerPromptBuilder::MAX_FEEDBACK_PROMPT_ENTRIES), $prompt);
        self::assertStringNotContainsString(\sprintf('Reason %d', ReviewerPromptBuilder::MAX_FEEDBACK_PROMPT_ENTRIES + 1), $prompt);
    }

    public function test_a_multi_line_reason_is_collapsed_to_a_single_feedback_line(): void
    {
        $reviewerPromptBuilder = $this->builderWithFeedback(false, [
            new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', "first line\nsecond   line"),
        ]);

        self::assertStringContainsString('(src/A.php): first line second line', $reviewerPromptBuilder->buildSystemPrompt());
    }

    /**
     * @param list<AcceptedFindingFeedback> $entries
     */
    private function builderWithFeedback(bool $useStructuredCollection, array $entries): ReviewerPromptBuilder
    {
        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $reviewerFeedbackHolder->set(new ReviewerFeedback($entries));

        return new ReviewerPromptBuilder($useStructuredCollection, reviewerFeedbackProvider: $reviewerFeedbackHolder);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Title for '.$filePath, 0.9),
            new CodeLocation($filePath, 1, 5),
            new VulnerabilityNarrative('Desc', 'vec', 'proof', 'fix'),
            'code',
        );
    }
}
