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

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\HiddenInputUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\HiddenCredentialPrompt;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture\RecordingSymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture\UnhideableSymfonyStyle;

final class HiddenCredentialPromptTest extends TestCase
{
    private const string QUESTION = 'Paste the API key (input stays hidden)';

    /**
     * @throws HiddenInputUnavailableException
     */
    public function test_it_returns_the_answer_without_the_whitespace_a_paste_brings(): void
    {
        self::assertSame('anthropic-test-key-typed', (new HiddenCredentialPrompt())->ask($this->symfonyStyleReading("  anthropic-test-key-typed \n"), self::QUESTION));
    }

    /**
     * @throws HiddenInputUnavailableException
     */
    public function test_it_treats_a_blank_answer_as_no_answer(): void
    {
        self::assertNull((new HiddenCredentialPrompt())->ask($this->symfonyStyleReading("   \n"), self::QUESTION));
    }

    /**
     * @throws HiddenInputUnavailableException
     */
    public function test_it_treats_the_end_of_input_as_no_answer(): void
    {
        self::assertNull((new HiddenCredentialPrompt())->ask($this->symfonyStyleReading(''), self::QUESTION));
    }

    /**
     * @throws HiddenInputUnavailableException
     */
    public function test_it_asks_nothing_of_an_input_that_cannot_prompt(): void
    {
        self::assertNull((new HiddenCredentialPrompt())->ask($this->symfonyStyleReading("anthropic-test-key-unread\n", false), self::QUESTION));
    }

    /**
     * @throws HiddenInputUnavailableException
     */
    public function test_it_refuses_rather_than_echo_when_the_terminal_cannot_hide_the_answer(): void
    {
        $this->expectException(HiddenInputUnavailableException::class);
        $this->expectExceptionMessage('cannot hide what is typed into it');

        (new HiddenCredentialPrompt())->ask(new UnhideableSymfonyStyle(new ArrayInput([]), new BufferedOutput()), self::QUESTION);
    }

    /**
     * @throws HiddenInputUnavailableException
     */
    public function test_it_keeps_the_answer_hidden_with_no_echoing_fallback(): void
    {
        $recordingSymfonyStyle = new RecordingSymfonyStyle(new ArrayInput([]), new BufferedOutput());

        self::assertSame('anthropic-test-key-recorded', (new HiddenCredentialPrompt())->ask($recordingSymfonyStyle, self::QUESTION));

        $question = $recordingSymfonyStyle->question;
        self::assertInstanceOf(Question::class, $question);
        self::assertSame(self::QUESTION, $question->getQuestion());
        self::assertTrue($question->isHidden());
        self::assertFalse($question->isHiddenFallback());
    }

    private function symfonyStyleReading(string $input, bool $interactive = true): SymfonyStyle
    {
        $stream = fopen('php://memory', 'r+');
        self::assertNotFalse($stream);
        fwrite($stream, $input);
        rewind($stream);

        $arrayInput = new ArrayInput([]);
        $arrayInput->setStream($stream);
        $arrayInput->setInteractive($interactive);

        return new SymfonyStyle($arrayInput, new BufferedOutput());
    }
}
