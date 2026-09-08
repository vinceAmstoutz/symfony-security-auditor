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
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Event\ConsoleErrorEvent;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use VinceAmstoutz\SecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SecurityAuditor\Command\AuditFailureExitCodeListener;
use VinceAmstoutz\SecurityAuditor\Command\ExitCode;

final class AuditFailureExitCodeListenerTest extends TestCase
{
    public function test_an_audit_run_error_reports_the_audit_failed_code(): void
    {
        $consoleErrorEvent = $this->makeEvent(new Command(AuditCommand::NAME));

        (new AuditFailureExitCodeListener())($consoleErrorEvent);

        self::assertSame(ExitCode::AuditFailed->value, $consoleErrorEvent->getExitCode());
    }

    public function test_another_command_keeps_the_console_default_code(): void
    {
        $consoleErrorEvent = $this->makeEvent(new Command('audit:diff'));

        (new AuditFailureExitCodeListener())($consoleErrorEvent);

        self::assertSame(ExitCode::Failure->value, $consoleErrorEvent->getExitCode());
    }

    public function test_an_unresolved_command_keeps_the_console_default_code(): void
    {
        $consoleErrorEvent = $this->makeEvent(null);

        (new AuditFailureExitCodeListener())($consoleErrorEvent);

        self::assertSame(ExitCode::Failure->value, $consoleErrorEvent->getExitCode());
    }

    private function makeEvent(?Command $command): ConsoleErrorEvent
    {
        return new ConsoleErrorEvent(
            new ArrayInput([]),
            new NullOutput(),
            new RuntimeException('boom'),
            $command,
        );
    }
}
