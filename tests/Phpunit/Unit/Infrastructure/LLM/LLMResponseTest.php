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
        // Without backslash-escape awareness, the `\"` would prematurely close the
        // string, exposing the `]` to the bracket counter and truncating extraction
        // at the wrong place. Pin the escape behavior.
        $content = 'prose: [{"title":"x \" ] y","other":"z"}] end';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([['title' => 'x " ] y', 'other' => 'z']], $data);
    }

    public function test_it_locks_extraction_length_to_closing_bracket_position(): void
    {
        // A `+1` → `+2` mutation on the substring length would include one byte
        // past the closing bracket. With a `{` immediately after the `]`, that
        // extra byte makes the substring invalid JSON, so the second decode
        // throws and the mutant is killed.
        $content = '[1,2]{garbage}';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    public function test_it_scans_for_opener_from_the_start_not_the_end_of_content(): void
    {
        // PHP returns the last character for `$content[-1]`. A mutation that flips
        // the opener-scan loop's initial index from `0` to `-1` would pick that
        // last character as the opener when it happens to be `[` or `{`, yielding
        // a different extracted substring than scanning forward from the start.
        // Content has a valid `[1,2]` early AND ends with `{`, so the original
        // recovers `[1,2]` while the mutant tries to extract from the trailing
        // `{` and fails to find a matching close → null → JsonException rethrow.
        $content = '[1,2] {';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame([1, 2], $data);
    }

    public function test_it_extracts_json_object_when_braces_are_the_first_opener(): void
    {
        // Pins the `{`-opener branch in `findFirstJsonOpener`: with no `[` earlier
        // in the content, a ReturnRemoval on the `{` branch would skip past the
        // opener, find no other opener later, and return null — collapsing back to
        // a JsonException rethrow. The successful object extraction proves the
        // branch returned its tuple.
        $content = 'prose {"key": "value"} suffix';
        $llmResponse = LLMResponse::create($content, 10, 5, 'claude', 'end_turn');

        $data = $llmResponse->parseJson();

        self::assertSame(['key' => 'value'], $data);
    }

    public function test_it_throws_on_invalid_json(): void
    {
        $llmResponse = LLMResponse::create('not json at all', 10, 5, 'claude', 'end_turn');

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
}
