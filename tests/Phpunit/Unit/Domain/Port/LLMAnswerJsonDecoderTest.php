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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Port;

use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMAnswerJsonDecoder;

final class LLMAnswerJsonDecoderTest extends TestCase
{
    #[DataProvider('answerCases')]
    public function test_it_decodes_the_json_an_answer_holds(string $answer, mixed $expected): void
    {
        self::assertSame($expected, LLMAnswerJsonDecoder::decode($answer));
    }

    /** @return iterable<string, array{string, mixed}> */
    public static function answerCases(): iterable
    {
        yield 'a bare object' => ['{"verdict": "ok"}', ['verdict' => 'ok']];
        yield 'an object in a Markdown fence' => ["```json\n{\"verdict\": \"ok\"}\n```", ['verdict' => 'ok']];
        yield 'an object after prose' => ['The verdict: {"verdict": "ok"}', ['verdict' => 'ok']];
        yield 'the last object stands for the verdict over quoted JSON before it' => ['Quoted {"x": 1} then {"verdict": "ok"}', ['verdict' => 'ok']];
        yield 'a prose bracket after the answer does not stand for it' => ['{"verdict": "ok"} as in [1]', ['verdict' => 'ok']];
        yield 'the first complete object of a truncated array' => ['[{"id": 1}, {"id": 2}, {"id":', ['id' => 1]];
    }

    public function test_it_recovers_a_block_opened_after_sixty_three_unclosed_openers(): void
    {
        self::assertSame(['a' => 1], LLMAnswerJsonDecoder::decode('Findings: '.str_repeat('[', 63).'{"a": 1}'));
    }

    public function test_it_gives_up_on_a_block_opened_after_sixty_four_unclosed_openers(): void
    {
        $this->expectException(JsonException::class);

        LLMAnswerJsonDecoder::decode('Findings: '.str_repeat('[', 64).'{"a": 1}');
    }

    public function test_it_rethrows_the_json_error_of_an_answer_that_is_all_unclosed_openers(): void
    {
        $this->expectException(JsonException::class);

        LLMAnswerJsonDecoder::decode('Findings: '.str_repeat('[', 10_000));
    }

    public function test_it_rethrows_the_json_error_when_no_block_decodes(): void
    {
        $this->expectException(JsonException::class);

        LLMAnswerJsonDecoder::decode('no json at all');
    }
}
