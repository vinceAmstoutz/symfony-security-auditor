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

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Exception\ExceedContextSizeException;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\CommandLineLimitExceptionInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentWorkingDirectory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\CliAgentCommandLineTooLongException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\CliAgentPromptTooLongException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;

final class CliAgentPlatformTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

    private const int LONGEST_COMMAND_LINE_ARGUMENT = 131071;

    private const int WINDOWS_PROMPT_ROOM = 7000;

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_a_prompt_longer_than_one_command_line_argument_can_carry_is_refused_as_too_large(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform, new CliAgentWorkingDirectory(), ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', new MessageBag(Message::ofUser(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1))));
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_a_prompt_longer_than_one_command_line_argument_can_carry_is_refused_by_the_command_line(): void
    {
        $this->expectException(CommandLineLimitExceptionInterface::class);
        $this->expectExceptionMessageContaining('The prompt is longer than the 131071 bytes one command-line argument of the CLI can carry.');

        (new CliAgentPlatform(self::createStub(PlatformInterface::class), new CliAgentWorkingDirectory(), ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', new MessageBag(Message::ofUser(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1))));
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_a_system_prompt_longer_than_one_command_line_argument_can_carry_is_refused_as_too_large(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform, new CliAgentWorkingDirectory(), ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', new MessageBag(Message::forSystem(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1)), Message::ofUser('Audit this.')));
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_a_prompt_as_long_as_one_command_line_argument_can_carry_reaches_the_cli_alone_with_its_isolating_options_in_its_working_directory(): void
    {
        $messageBag = new MessageBag(Message::ofUser(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT)));
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('OK')), new InMemoryRawResult());
        $platform = $this->createMock(PlatformInterface::class);
        $cliAgentWorkingDirectory = new CliAgentWorkingDirectory();
        $platform->expects(self::once())->method('invoke')->with('opus', $messageBag, ['tools' => [], 'strict_mcp_config' => true, 'cwd' => $cliAgentWorkingDirectory->path])->willReturn($deferredResult);

        self::assertSame($deferredResult, (new CliAgentPlatform($platform, $cliAgentWorkingDirectory, ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', $messageBag, ['max_tokens' => 10]));
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_a_prompt_given_as_text_reaches_the_cli_unmeasured(): void
    {
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('OK')), new InMemoryRawResult());
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::once())->method('invoke')->with('opus', str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1))->willReturn($deferredResult);

        self::assertSame($deferredResult, (new CliAgentPlatform($platform, new CliAgentWorkingDirectory(), ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1)));
    }

    public function test_it_answers_with_the_model_catalog_of_the_cli(): void
    {
        $modelCatalog = new FallbackModelCatalog();
        $platform = self::createStub(PlatformInterface::class);
        $platform->method('getModelCatalog')->willReturn($modelCatalog);

        self::assertSame($modelCatalog, (new CliAgentPlatform($platform, new CliAgentWorkingDirectory(), ['tools' => [], 'strict_mcp_config' => true]))->getModelCatalog());
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_prompts_that_share_one_command_line_argument_are_refused_as_too_large_together(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform, new CliAgentWorkingDirectory(), ['sandbox' => 'read-only'], promptsShareOneArgument: true))->invoke('gpt-6.2-astra', $this->framedPrompts(self::LONGEST_COMMAND_LINE_ARGUMENT + 1));
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_prompts_that_fill_their_shared_command_line_argument_exactly_reach_the_cli(): void
    {
        $messageBag = $this->framedPrompts(self::LONGEST_COMMAND_LINE_ARGUMENT);
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('OK')), new InMemoryRawResult());
        $platform = $this->createMock(PlatformInterface::class);
        $cliAgentWorkingDirectory = new CliAgentWorkingDirectory();
        $platform->expects(self::once())->method('invoke')->with('gpt-6.2-astra', $messageBag, ['sandbox' => 'read-only', 'cwd' => $cliAgentWorkingDirectory->path])->willReturn($deferredResult);

        self::assertSame($deferredResult, (new CliAgentPlatform($platform, $cliAgentWorkingDirectory, ['sandbox' => 'read-only'], promptsShareOneArgument: true))->invoke('gpt-6.2-astra', $messageBag));
    }

    /**
     * @throws CliAgentPromptTooLongException
     */
    public function test_on_windows_instructions_longer_than_the_command_line_leaves_the_prompts_stop_the_run_instead_of_splitting_it(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        try {
            (new CliAgentPlatform($platform, new CliAgentWorkingDirectory(), ['tools' => []], onWindows: true))->invoke('opus', new MessageBag(Message::forSystem(str_repeat('a', self::WINDOWS_PROMPT_ROOM + 1)), Message::ofUser('Audit this.')));
            self::fail('Instructions the Windows command line cannot carry reached the CLI.');
        } catch (CliAgentCommandLineTooLongException $cliAgentCommandLineTooLongException) {
            self::assertSame(\sprintf("On Windows, the command line that starts the CLI of a Claude or ChatGPT subscription holds at most 8191 characters, but the auditor's instructions alone take %d bytes, so the audit cannot run on a subscription there. Run it under WSL, on Linux or macOS, or on an API platform.", self::WINDOWS_PROMPT_ROOM + 1), $cliAgentCommandLineTooLongException->getMessage());
        }
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_on_windows_prompts_longer_than_the_command_line_leaves_them_are_refused_as_too_large(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform, new CliAgentWorkingDirectory(), ['tools' => []], onWindows: true))->invoke('opus', new MessageBag(Message::forSystem(str_repeat('a', self::WINDOWS_PROMPT_ROOM)), Message::ofUser('b')));
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_on_windows_prompts_longer_than_the_command_line_leaves_them_are_refused_by_the_command_line(): void
    {
        $this->expectException(CommandLineLimitExceptionInterface::class);
        $this->expectExceptionMessageContaining('The prompt is longer than the 7000 bytes the Windows command line of the CLI leaves it.');

        (new CliAgentPlatform(self::createStub(PlatformInterface::class), new CliAgentWorkingDirectory(), ['tools' => []], onWindows: true))->invoke('opus', new MessageBag(Message::forSystem(str_repeat('a', self::WINDOWS_PROMPT_ROOM)), Message::ofUser('b')));
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    public function test_on_windows_prompts_that_fill_the_room_the_command_line_leaves_them_reach_the_cli(): void
    {
        $messageBag = new MessageBag(Message::forSystem(str_repeat('a', self::WINDOWS_PROMPT_ROOM - 1)), Message::ofUser('b'));
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('OK')), new InMemoryRawResult());
        $platform = $this->createMock(PlatformInterface::class);
        $cliAgentWorkingDirectory = new CliAgentWorkingDirectory();
        $platform->expects(self::once())->method('invoke')->with('opus', $messageBag, ['tools' => [], 'cwd' => $cliAgentWorkingDirectory->path])->willReturn($deferredResult);

        self::assertSame($deferredResult, (new CliAgentPlatform($platform, $cliAgentWorkingDirectory, ['tools' => []], onWindows: true))->invoke('opus', $messageBag));
    }

    private function framedPrompts(int $framedLength): MessageBag
    {
        $system = 'Be terse.';

        return new MessageBag(Message::forSystem($system), Message::ofUser(str_repeat('b', $framedLength - \strlen(\sprintf("[System]\n%s\n\n[User]\n", $system)))));
    }
}
