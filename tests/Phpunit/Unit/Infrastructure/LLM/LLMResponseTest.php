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
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

final class LLMResponseTest extends TestCase
{
    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_creates_and_exposes_properties(): void
    {
        $llmResponse = LLMResponse::of('Hello world', 'claude-opus', 'end_turn', TokenUsageSnapshot::of(100, 50));

        self::assertSame('Hello world', $llmResponse->content());
        self::assertSame(100, $llmResponse->inputTokens());
        self::assertSame(50, $llmResponse->outputTokens());
        self::assertSame('claude-opus', $llmResponse->model());
        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertSame(150, $llmResponse->totalTokens());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_cache_tokens_default_to_zero_when_not_supplied(): void
    {
        $llmResponse = LLMResponse::of('Hello world', 'claude-opus', 'end_turn', TokenUsageSnapshot::of(100, 50));

        self::assertSame(0, $llmResponse->cacheReadTokens());
        self::assertSame(0, $llmResponse->cacheCreationTokens());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_exposes_supplied_cache_tokens(): void
    {
        $llmResponse = LLMResponse::of('Hello world', 'claude-opus', 'end_turn', TokenUsageSnapshot::of(100, 50, 30, 12));

        self::assertSame(30, $llmResponse->cacheReadTokens());
        self::assertSame(12, $llmResponse->cacheCreationTokens());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_detects_empty_content(): void
    {
        $llmResponse = LLMResponse::of('  ', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
        self::assertTrue($llmResponse->isEmpty());

        $notEmpty = LLMResponse::of('{"key": "value"}', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
        self::assertFalse($notEmpty->isEmpty());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_parses_json_content(): void
    {
        $llmResponse = LLMResponse::of('{"vulnerabilities": []}', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
        $data = $llmResponse->parseJson();

        self::assertArrayHasKey('vulnerabilities', $data);
        self::assertEmpty($data['vulnerabilities']);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_strips_markdown_fences_before_parsing(): void
    {
        $content = "```json\n{\"key\": \"value\"}\n```";
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
        $data = $llmResponse->parseJson();

        self::assertSame('value', $data['key']);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_extracts_json_array_when_wrapped_in_leading_prose(): void
    {
        $content = "I analyzed the code carefully:\n\n[{\"title\": \"finding\"}]";
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'finding']], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_extracts_json_array_when_followed_by_trailing_prose(): void
    {
        $content = "[{\"title\": \"finding\"}]\n\nThat concludes my analysis.";
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'finding']], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_extracts_balanced_json_array_with_nested_objects_from_prose(): void
    {
        // Validates that the extractor's balanced-brace walker correctly handles
        // nested `{` / `}` inside the outer `[ ... ]` block.
        $content = 'Found these issues: [{"id":1,"meta":{"score":0.9}}] — done.';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([['id' => 1, 'meta' => ['score' => 0.9]]], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_ignores_brackets_inside_strings_when_extracting(): void
    {
        // String contents must not affect depth counting — `]` inside a JSON
        // string would otherwise close the outer array prematurely.
        $content = 'note: [{"title":"contains ] bracket"}] end';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'contains ] bracket']], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_treats_escaped_quote_as_part_of_string_during_extraction(): void
    {
        $content = 'prose: [{"title":"x \" ] y","other":"z"}] end';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'x " ] y', 'other' => 'z']], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_skips_a_leading_quoted_string_with_escaped_bracket_before_the_real_array(): void
    {
        $content = 'note "a \[9,9] b" then [1,2] end';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_treats_empty_json_string_as_closed_during_extraction(): void
    {
        $content = 'see [{"a":"","b":9}] end';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([['a' => '', 'b' => 9]], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_throws_when_content_is_empty_after_stripping_fences(): void
    {
        $llmResponse = LLMResponse::of('```json``` ', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(JsonException::class);

        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_locks_extraction_length_to_closing_bracket_position(): void
    {
        $content = '[1,2]{garbage}';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_scans_for_opener_from_the_start_not_the_end_of_content(): void
    {
        $content = '[1,2] {';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_extracts_json_object_when_braces_are_the_first_opener(): void
    {
        $content = 'prose {"key": "value"} suffix';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame(['key' => 'value'], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_recovers_trailing_empty_array_when_prose_mentions_php_array_access(): void
    {
        $content = "  The controller has a route condition restricting it to dev/test only. No exploitable issue.\n  \n"
            .'  The templates given are mostly safe - default escaping, translated strings, no `|raw` on user input.'
            .' The recommendation card displays `recommendation.contents[locale]` without escaping override -'
            ." but since it's autoescaped HTML, no XSS.\n  \n"
            ."  No real exploitable vulnerabilities found in the provided files.\n  \n  []  ";
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_recovers_trailing_vulnerability_list_when_prose_contains_undecodable_bracket_example(): void
    {
        $content = 'I noticed templates rendering `recommendation.contents[locale]` and'
            ." constructs like [array key access] in helpers. Final list of findings:\n"
            .'[{"type":"sql_injection","severity":"high","title":"Unsafe query",'
            .'"description":"User input concatenated into SQL.","file_path":"src/Controller/X.php",'
            .'"line_start":42,"line_end":42,"vulnerable_code":"$em->getConnection()->executeQuery($sql)",'
            .'"attack_vector":"id parameter","proof":"id=1 OR 1=1","remediation":"Use parameter binding.",'
            .'"confidence":0.9}]';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

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

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_recovers_a_json_block_after_an_unpaired_quote_in_the_preceding_prose(): void
    {
        $content = 'The vulnerability report follows. Note: user input is 5" from validation. '
            .'[{"type":"sql_injection","severity":"high","title":"X","confidence":0.9}]';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([[
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => 'X',
            'confidence' => 0.9,
        ]], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_recovers_a_json_object_after_an_unpaired_quote_in_the_preceding_prose(): void
    {
        $content = 'The pipe is 5" long: { "key": "value" }';
        $llmResponse = LLMResponse::of($content, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame(['key' => 'value'], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_throws_on_invalid_json(): void
    {
        $llmResponse = LLMResponse::of('not json at all', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_recovery_is_skipped_when_first_character_is_an_object_opener_spanning_full_content(): void
    {
        $llmResponse = LLMResponse::of('{xyz: [1]}', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_recovery_is_skipped_when_first_character_opens_a_block_spanning_full_content(): void
    {
        $llmResponse = LLMResponse::of('[xyz, [1,2]]', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_recovery_invokes_object_branch_only_on_brace_character(): void
    {
        $llmResponse = LLMResponse::of('}{}', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_recovery_iterator_starts_at_index_zero_not_minus_one(): void
    {
        $llmResponse = LLMResponse::of('[1,2]"', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_throws_when_prose_contains_unbalanced_bracket_with_no_closer(): void
    {
        // Prose mentions `[` but no matching `]` ever appears — every opener
        // candidate fails to scan a balanced block, so the original
        // `JsonException` propagates rather than masking the failure.
        $llmResponse = LLMResponse::of('prose with [no real json here', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_throws_when_prose_surrounds_no_balanced_json_block(): void
    {
        // Unbalanced braces (`{{{` with no matching closers) — extractor returns
        // null and the original JsonException is rethrown.
        $llmResponse = LLMResponse::of('invalid json {{{', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_throws_when_json_is_not_array(): void
    {
        $llmResponse = LLMResponse::of('"just a string"', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(RuntimeException::class);
        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_trims_surrounding_whitespace_before_parsing(): void
    {
        $llmResponse = LLMResponse::of('   {"key": "value"}   ', 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));
        $data = $llmResponse->parseJson();

        self::assertSame('value', $data['key']);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_parse_json_succeeds_at_511_nesting_levels(): void
    {
        // depth=512 allows up to 511 levels; depth=511 mutant would reject this → kills DecrementInteger
        $json = str_repeat('[', 511).str_repeat(']', 511);
        $llmResponse = LLMResponse::of($json, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $data = $llmResponse->parseJson();

        self::assertCount(1, $data);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_parse_json_throws_at_512_nesting_levels(): void
    {
        // depth=512 rejects 512 levels; depth=513 mutant would accept it → kills IncrementInteger
        $json = str_repeat('[', 512).str_repeat(']', 512);
        $llmResponse = LLMResponse::of($json, 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(JsonException::class);
        $llmResponse->parseJson();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_parse_json_strips_null_bytes_before_decoding(): void
    {
        // trim() removes \x00 (null byte); json_decode does NOT handle null bytes.
        // MethodCallRemoval on trim() would leave \x00 in content → JsonException.
        $llmResponse = LLMResponse::of("\x00[1, 2, 3]\x00", 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));

        self::assertSame([1, 2, 3], $llmResponse->parseJson());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_parse_json_trims_non_json_whitespace_around_scalar_to_reach_array_guard(): void
    {
        $llmResponse = LLMResponse::of("\x0b\"scalar\"\x0b", 'claude', 'end_turn', TokenUsageSnapshot::of(10, 5));

        $this->expectException(RuntimeException::class);
        $llmResponse->parseJson();
    }

    /**
     * @deprecated covers the deprecated {@see LLMResponse::create()} delegator until it is removed in 2.0.
     *
     * @throws InvalidTokenUsageException
     */
    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_deprecated_create_maps_every_field(): void
    {
        $this->expectUserDeprecationMessageMatches('/LLMResponse::create\(\) is deprecated, use LLMResponse::of\(\) instead\./');

        $llmResponse = LLMResponse::create(
            content: 'body',
            inputTokens: 11,
            outputTokens: 22,
            model: 'claude-opus',
            stopReason: 'end_turn',
            cacheReadTokens: 33,
            cacheCreationTokens: 44,
        );

        self::assertSame('body', $llmResponse->content());
        self::assertSame(11, $llmResponse->inputTokens());
        self::assertSame(22, $llmResponse->outputTokens());
        self::assertSame('claude-opus', $llmResponse->model());
        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertSame(33, $llmResponse->cacheReadTokens());
        self::assertSame(44, $llmResponse->cacheCreationTokens());

        self::assertEquals(
            LLMResponse::of('body', 'claude-opus', 'end_turn', TokenUsageSnapshot::of(11, 22, 33, 44)),
            $llmResponse,
        );
    }

    /**
     * @deprecated covers the deprecated {@see LLMResponse::create()} delegator until it is removed in 2.0.
     */
    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_deprecated_create_defaults_cache_tokens_to_zero(): void
    {
        $this->expectUserDeprecationMessageMatches('/LLMResponse::create\(\) is deprecated, use LLMResponse::of\(\) instead\./');

        $llmResponse = LLMResponse::create('body', 11, 22, 'claude-opus', 'end_turn');

        self::assertSame(0, $llmResponse->cacheReadTokens());
        self::assertSame(0, $llmResponse->cacheCreationTokens());
    }
}
