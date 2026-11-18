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
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuthTestCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConnectionCheckInterface;

final class AuthTestCommandTest extends TestCase
{
    public function test_it_reports_a_provider_that_accepted_the_key(): void
    {
        $commandTester = $this->commandTester(null);

        $commandTester->execute([]);

        self::assertStringContainsString('[OK] Your API key works: the provider answered a test request.', $commandTester->getDisplay());
    }

    public function test_it_fails_with_the_reason_the_provider_gave(): void
    {
        $commandTester = $this->commandTester('HTTP 401: invalid x-api-key');

        $exitCode = $commandTester->execute([]);

        self::assertSame([Command::FAILURE, true], [$exitCode, str_contains($commandTester->getDisplay(), 'The provider did not answer: HTTP 401: invalid x-api-key')]);
    }

    private function commandTester(?string $failureReason): CommandTester
    {
        $connectionCheck = self::createStub(ConnectionCheckInterface::class);
        $connectionCheck->method('failureReason')->willReturn($failureReason);

        return new CommandTester(new AuthTestCommand($connectionCheck));
    }
}
