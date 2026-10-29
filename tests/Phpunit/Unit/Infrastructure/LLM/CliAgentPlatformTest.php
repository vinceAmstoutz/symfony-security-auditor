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
use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatform;

final class CliAgentPlatformTest extends TestCase
{
    private const int LONGEST_COMMAND_LINE_ARGUMENT = 131071;

    public function test_a_prompt_longer_than_one_command_line_argument_can_carry_is_refused_as_too_large(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform))->invoke('opus', new MessageBag(Message::ofUser(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1))));
    }

    public function test_a_system_prompt_longer_than_one_command_line_argument_can_carry_is_refused_as_too_large(): void
    {
        $platform = $this->createMock(PlatformInterface::class);
        $platform->expects(self::never())->method('invoke');

        $this->expectException(ExceedContextSizeException::class);

        (new CliAgentPlatform($platform))->invoke('opus', new MessageBag(Message::forSystem(str_repeat('a', self::LONGEST_COMMAND_LINE_ARGUMENT + 1)), Message::ofUser('Audit this.')));
    }
}
