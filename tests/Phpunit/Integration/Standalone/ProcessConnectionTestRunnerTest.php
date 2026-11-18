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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\SelfInvocation;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\ProcessConnectionTestRunner;

final class ProcessConnectionTestRunnerTest extends TestCase
{
    public function test_it_shows_what_the_doctor_connection_check_prints(): void
    {
        $bufferedOutput = new BufferedOutput();

        (new ProcessConnectionTestRunner(new SelfInvocation(__DIR__.'/Fixture/ConnectionTest/answering-binary.php')))->run($bufferedOutput);

        self::assertSame('ran: doctor --check-connection'.\PHP_EOL, $bufferedOutput->fetch());
    }

    public function test_it_reports_a_connection_check_that_failed(): void
    {
        self::assertFalse((new ProcessConnectionTestRunner(new SelfInvocation(__DIR__.'/Fixture/ConnectionTest/refusing-binary.php')))->run(new BufferedOutput()));
    }

    public function test_it_says_why_it_could_not_start_the_check(): void
    {
        $bufferedOutput = new BufferedOutput();

        $succeeded = (new ProcessConnectionTestRunner(new SelfInvocation('', 'micro')))->run($bufferedOutput);

        self::assertSame([false, true], [$succeeded, str_contains($bufferedOutput->fetch(), 'The connection test could not start:')]);
    }
}
