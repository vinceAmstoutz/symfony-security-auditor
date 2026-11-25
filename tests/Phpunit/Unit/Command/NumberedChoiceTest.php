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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\NumberedChoice;

final class NumberedChoiceTest extends TestCase
{
    private const array LABELS = ['claude-opus-5-5 ($5 in, $25 out per million tokens)', 'claude-sonnet-5-5 ($3 in, $15 out per million tokens)'];

    private const array VALUES = ['claude-opus-5-5', 'claude-sonnet-5-5'];

    #[DataProvider('answers')]
    public function test_an_answer_naming_a_choice_by_its_number_its_label_or_its_value_picks_the_value_it_stands_for(string $answer, string $expected): void
    {
        self::assertSame($expected, NumberedChoice::ask($this->styleAnswering($answer), 'Which model?', self::LABELS, 'claude-opus-5-5', self::VALUES));
    }

    #[DataProvider('answers')]
    public function test_a_question_naming_its_default_by_value_maps_an_answer_the_same_way(string $answer, string $expected): void
    {
        self::assertSame($expected, NumberedChoice::askNamingTheDefaultValue($this->styleAnswering($answer), 'Which model?', self::LABELS, 'claude-opus-5-5', self::VALUES));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function answers(): iterable
    {
        yield 'a number' => ['2', 'claude-sonnet-5-5'];
        yield 'a label the terminal completed' => ['claude-sonnet-5-5 ($3 in, $15 out per million tokens)', 'claude-sonnet-5-5'];
        yield 'a listed value' => ['claude-sonnet-5-5', 'claude-sonnet-5-5'];
        yield 'any other value' => ['claude-haiku-5-5', 'claude-haiku-5-5'];
        yield 'a number past the list' => ['3', '3'];
        yield 'no answer' => ['', 'claude-opus-5-5'];
    }

    private function styleAnswering(string $answer): SymfonyStyle
    {
        $stream = fopen('php://memory', 'r+');
        self::assertIsResource($stream);
        fwrite($stream, $answer."\n");
        rewind($stream);

        $arrayInput = new ArrayInput([]);
        $arrayInput->setStream($stream);

        return new SymfonyStyle($arrayInput, new NullOutput());
    }
}
