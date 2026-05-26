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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use JsonException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

final class LLMResponseTest extends TestCase
{
    public function test_it_creates_and_exposes_properties(): void
    {
        $llmResponse = LLMResponse::create('Hello world', 100, 50, 'claude-opus', 'end_turn');

        self::assertSame('Hello world', $llmResponse->content());
        self::assertSame(100, $llmResponse->inputTokens());
        self::assertSame(50, $llmResponse->outputTokens());
        self::assertSame('claude-opus', $llmResponse->model());
        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertSame(150, $llmResponse->totalTokens());
    }

    public function test_it_detects_empty_content(): void
    {
        $llmResponse = LLMResponse::create('  ', 10, 5, 'claude', 'end_turn');
        self::assertTrue($llmResponse->isEmpty());

        $notEmpty = LLMResponse::create('{"key": "value"}', 10, 5, 'claude', 'end_turn');
        self::assertFalse($notEmpty->isEmpty());
    }

    public function test_it_parses_json_content(): void
    {
        $llmResponse = LLMResponse::create('{"vulnerabilities": []}', 10, 5, 'claude', 'end_turn');
        $data = $llmResponse->parseJson();

        self::assertArrayHasKey('vulnerabilities', $data);
        self::assertEmpty($data['vulnerabilities']);
    }

    public function test_it_strips_markdown_fences_before_parsing(): void
    {
        $content = "```json\n{\"key\": \"value\"}\n```";
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');
        $data = $llmResponse->parseJson();

        self::assertSame('value', $data['key']);
    }

    public function test_it_extracts_json_array_when_wrapped_in_leading_prose(): void
    {
        $content = "I analyzed the code carefully:\n\n[{\"title\": \"finding\"}]";
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'finding']], $data);
    }

    public function test_it_extracts_json_array_when_followed_by_trailing_prose(): void
    {
        $content = "[{\"title\": \"finding\"}]\n\nThat concludes my analysis.";
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'finding']], $data);
    }

    public function test_it_extracts_balanced_json_array_with_nested_objects_from_prose(): void
    {
        // Validates that the extractor's balanced-brace walker correctly handles
        // nested `{` / `}` inside the outer `[ ... ]` block.
        $content = 'Found these issues: [{"id":1,"meta":{"score":0.9}}] — done.';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([['id' => 1, 'meta' => ['score' => 0.9]]], $data);
    }

    public function test_it_ignores_brackets_inside_strings_when_extracting(): void
    {
        // String contents must not affect depth counting — `]` inside a JSON
        // string would otherwise close the outer array prematurely.
        $content = 'note: [{"title":"contains ] bracket"}] end';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'contains ] bracket']], $data);
    }

    public function test_it_treats_escaped_quote_as_part_of_string_during_extraction(): void
    {
        $content = 'prose: [{"title":"x \" ] y","other":"z"}] end';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'x " ] y', 'other' => 'z']], $data);
    }

    public function test_it_locks_extraction_length_to_closing_bracket_position(): void
    {
        $content = '[1,2]{garbage}';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    public function test_it_scans_for_opener_from_the_start_not_the_end_of_content(): void
    {
        $content = '[1,2] {';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    public function test_it_extracts_json_object_when_braces_are_the_first_opener(): void
    {
        $content = 'prose {"key": "value"} suffix';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame(['key' => 'value'], $data);
    }

    public function test_it_recovers_trailing_empty_array_when_prose_mentions_php_array_access(): void
    {
        $content = "  The controller has a route condition restricting it to dev/test only. No exploitable issue.\n  \n"
            .'  The templates given are mostly safe - default escaping, translated strings, no `|raw` on user input.'
            .' The recommendation card displays `recommendation.contents[locale]` without escaping override -'
            ." but since it's autoescaped HTML, no XSS.\n  \n"
            ."  No real exploitable vulnerabilities found in the provided files.\n  \n  []  ";
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([], $data);
    }

    public function test_it_recovers_trailing_vulnerability_list_when_prose_contains_undecodable_bracket_example(): void
    {
        $content = 'I noticed templates rendering `recommendation.contents[locale]` and'
            ." constructs like [array key access] in helpers. Final list of findings:\n"
            .'[{"type":"sql_injection","severity":"high","title":"Unsafe query",'
            .'"description":"User input concatenated into SQL.","file_path":"src/Controller/X.php",'
            .'"line_start":42,"line_end":42,"vulnerable_code":"$em->getConnection()->executeQuery($sql)",'
            .'"attack_vector":"id parameter","proof":"id=1 OR 1=1","remediation":"Use parameter binding.",'
            .'"confidence":0.9}]';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([[
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => 'Unsafe query',
            'description' => 'User input concatenated into SQL.',
            'file_path' => 'src/Controller/X.php',
            'line_start' => 42,
            'line_end' => 42,
            'vulnerable_code' => '$em->getConnection()->executeQuery($sql)',
            'attack_vector' => 'id parameter',
            'proof' => 'id=1 OR 1=1',
            'remediation' => 'Use parameter binding.',
            'confidence' => 0.9,
        ]], $data);
    }

    public function test_it_throws_on_invalid_json(): void
    {
        $llmResponse = LLMResponse::create('not json at all', 10, 5, 'claude', 'end_turn');

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    public function test_recovery_is_skipped_when_first_character_is_an_object_opener_spanning_full_content(): void
    {
        $llmResponse = LLMResponse::create('{xyz: [1]}', 10, 5, 'claude', 'end_turn');

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    public function test_recovery_is_skipped_when_first_character_opens_a_block_spanning_full_content(): void
    {
        $llmResponse = LLMResponse::create('[xyz, [1,2]]', 10, 5, 'claude', 'end_turn');

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    public function test_recovery_invokes_object_branch_only_on_brace_character(): void
    {
        $llmResponse = LLMResponse::create('}{}', 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([], $data);
    }

    public function test_recovery_iterator_starts_at_index_zero_not_minus_one(): void
    {
        $llmResponse = LLMResponse::create('[1,2]"', 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    public function test_it_throws_when_prose_contains_unbalanced_bracket_with_no_closer(): void
    {
        // Prose mentions `[` but no matching `]` ever appears — every opener
        // candidate fails to scan a balanced block, so the original
        // `JsonException` propagates rather than masking the failure.
        $llmResponse = LLMResponse::create('prose with [no real json here', 10, 5, 'claude', 'end_turn');

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    public function test_it_throws_when_prose_surrounds_no_balanced_json_block(): void
    {
        // Unbalanced braces (`{{{` with no matching closers) — extractor returns
        // null and the original JsonException is rethrown.
        $llmResponse = LLMResponse::create('invalid json {{{', 10, 5, 'claude', 'end_turn');

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    public function test_it_throws_when_json_is_not_array(): void
    {
        $llmResponse = LLMResponse::create('"just a string"', 10, 5, 'claude', 'end_turn');

        $this->expectException(RuntimeException::class);
        $llmResponse->parseJson();
    }

    public function test_it_trims_surrounding_whitespace_before_parsing(): void
    {
        $llmResponse = LLMResponse::create('   {"key": "value"}   ', 10, 5, 'claude', 'end_turn');
        $data = $llmResponse->parseJson();

        self::assertSame('value', $data['key']);
    }

    public function test_parse_json_succeeds_at_511_nesting_levels(): void
    {
        // depth=512 allows up to 511 levels; depth=511 mutant would reject this → kills DecrementInteger
        $json = str_repeat('[', 511).str_repeat(']', 511);
        $llmResponse = LLMResponse::create($json, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertCount(1, $data);
    }

    public function test_parse_json_throws_at_512_nesting_levels(): void
    {
        // depth=512 rejects 512 levels; depth=513 mutant would accept it → kills IncrementInteger
        $json = str_repeat('[', 512).str_repeat(']', 512);
        $llmResponse = LLMResponse::create($json, 10, 5, 'claude', 'end_turn');

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    public function test_parse_json_strips_null_bytes_before_decoding(): void
    {
        // trim() removes \x00 (null byte); json_decode does NOT handle null bytes.
        // MethodCallRemoval on trim() would leave \x00 in content → JsonException.
        $llmResponse = LLMResponse::create("\x00[1, 2, 3]\x00", 0, 0, 'test', 'end_turn');

        self::assertSame([1, 2, 3], $llmResponse->parseJson());
    }

    public function test_parse_json_trims_non_json_whitespace_around_scalar_to_reach_array_guard(): void
    {
        // Vertical tab (\x0b) is removed by `trim()` but rejected by `json_decode`
        // as a control character — and unlike an array payload, a scalar offers
        // no `[`/`{` opener for the balanced-block extractor to recover from.
        // With `trim()`: the inner `"scalar"` decodes and fails the `!is_array`
        // guard → RuntimeException. Without `trim()` (UnwrapTrim mutant): the
        // first decode throws on `\x0b`, the extractor finds no opener, and the
        // original JsonException is rethrown — pins the `trim()` call.
        $llmResponse = LLMResponse::create("\x0b\"scalar\"\x0b", 10, 5, 'claude', 'end_turn');

        $this->expectException(RuntimeException::class);
        $llmResponse->parseJson();
    }
}
