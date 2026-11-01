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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatform;

final class CliAgentPlatformTest extends TestCase
{
    private const int LONGEST_COMMAND_LINE_ARGUMENT = 131071;

    public function test_a_prompt_longer_than_one_command_line_argument_can_carry_is_refused_as_too_large(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform, ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', new MessageBag(Message::ofUser(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1))));
    }

    public function test_a_system_prompt_longer_than_one_command_line_argument_can_carry_is_refused_as_too_large(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform, ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', new MessageBag(Message::forSystem(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1)), Message::ofUser('Audit this.')));
    }

    public function test_a_prompt_as_long_as_one_command_line_argument_can_carry_reaches_the_cli_alone_with_its_isolating_options(): void
    {
        $messageBag = new MessageBag(Message::ofUser(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT)));
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('OK')), new InMemoryRawResult());
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::once())->method('invoke')->with('opus', $messageBag, ['tools' => [], 'strict_mcp_config' => true])->willReturn($deferredResult);

        self::assertSame($deferredResult, (new CliAgentPlatform($platform, ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', $messageBag, ['max_tokens' => 10]));
    }

    public function test_a_prompt_given_as_text_reaches_the_cli_unmeasured(): void
    {
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('OK')), new InMemoryRawResult());
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::once())->method('invoke')->with('opus', str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1))->willReturn($deferredResult);

        self::assertSame($deferredResult, (new CliAgentPlatform($platform, ['tools' => [], 'strict_mcp_config' => true]))->invoke('opus', str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1)));
    }

    public function test_it_answers_with_the_model_catalog_of_the_cli(): void
    {
        $modelCatalog = new FallbackModelCatalog();
        $platform = self::createStub(PlatformInterface::class);
        $platform->method('getModelCatalog')->willReturn($modelCatalog);

        self::assertSame($modelCatalog, (new CliAgentPlatform($platform, ['tools' => [], 'strict_mcp_config' => true]))->getModelCatalog());
    }

    public function test_prompts_that_share_one_command_line_argument_are_refused_as_too_large_together(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform, ['sandbox' => 'read-only'], promptsShareOneArgument: true))->invoke('gpt-5.4', $this->framedPrompts(self::LONGEST_COMMAND_LINE_ARGUMENT + 1));
    }

    public function test_prompts_that_fill_their_shared_command_line_argument_exactly_reach_the_cli(): void
    {
        $messageBag = $this->framedPrompts(self::LONGEST_COMMAND_LINE_ARGUMENT);
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('OK')), new InMemoryRawResult());
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::once())->method('invoke')->with('gpt-5.4', $messageBag, ['sandbox' => 'read-only'])->willReturn($deferredResult);

        self::assertSame($deferredResult, (new CliAgentPlatform($platform, ['sandbox' => 'read-only'], promptsShareOneArgument: true))->invoke('gpt-5.4', $messageBag));
    }

    private function framedPrompts(int $framedLength): MessageBag
    {
        $system = 'Be terse.';

        return new MessageBag(Message::forSystem($system), Message::ofUser(str_repeat('b', $framedLength - \strlen(\sprintf("[System]\n%s\n\n[User]\n", $system)))));
    }
}
