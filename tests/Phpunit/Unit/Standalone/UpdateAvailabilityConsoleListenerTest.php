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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Standalone;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Event\ConsoleTerminateEvent;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateAvailabilityNotifierInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\UpdateAvailabilityConsoleListener;

final class UpdateAvailabilityConsoleListenerTest extends TestCase
{
    private const string NOTICE = 'An update is available.';

    public function test_it_writes_the_notice_to_the_error_output_on_an_interactive_run(): void
    {
        $bufferedOutput = new BufferedOutput();
        $consoleOutput = new ConsoleOutput();
        $consoleOutput->setErrorOutput($bufferedOutput);

        ($this->listenerReturning(self::NOTICE))($this->terminateEvent($consoleOutput, true));

        self::assertStringContainsString(self::NOTICE, $bufferedOutput->fetch());
    }

    public function test_it_writes_to_the_provided_output_when_it_is_not_a_console_output(): void
    {
        $bufferedOutput = new BufferedOutput();

        ($this->listenerReturning(self::NOTICE))($this->terminateEvent($bufferedOutput, true));

        self::assertStringContainsString(self::NOTICE, $bufferedOutput->fetch());
    }

    public function test_it_stays_silent_on_a_non_interactive_run(): void
    {
        $bufferedOutput = new BufferedOutput();

        ($this->listenerReturning(self::NOTICE))($this->terminateEvent($bufferedOutput, false));

        self::assertSame('', $bufferedOutput->fetch());
    }

    public function test_it_stays_silent_when_no_update_is_available(): void
    {
        $bufferedOutput = new BufferedOutput();

        ($this->listenerReturning(null))($this->terminateEvent($bufferedOutput, true));

        self::assertSame('', $bufferedOutput->fetch());
    }

    public function test_it_stays_silent_when_update_checks_are_disabled(): void
    {
        $bufferedOutput = new BufferedOutput();

        ($this->listenerReturning(self::NOTICE, true))($this->terminateEvent($bufferedOutput, true));

        self::assertSame('', $bufferedOutput->fetch());
    }

    private function listenerReturning(?string $notice, bool $disabled = false): UpdateAvailabilityConsoleListener
    {
        $updateAvailabilityNotifier = self::createStub(UpdateAvailabilityNotifierInterface::class);
        $updateAvailabilityNotifier->method('availableUpdateNotice')->willReturn($notice);

        return new UpdateAvailabilityConsoleListener($updateAvailabilityNotifier, '1.0.0', $disabled);
    }

    private function terminateEvent(OutputInterface $output, bool $interactive): ConsoleTerminateEvent
    {
        $arrayInput = new ArrayInput([]);
        $arrayInput->setInteractive($interactive);

        return new ConsoleTerminateEvent(new Command('test'), $arrayInput, $output, 0);
    }
}
