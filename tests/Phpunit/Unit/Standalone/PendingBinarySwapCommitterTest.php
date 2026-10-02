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
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Filesystem\Exception\IOException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PendingBinarySwap;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\PendingBinarySwapCommitter;

final class PendingBinarySwapCommitterTest extends TestCase
{
    public function test_it_fails_the_process_when_the_deferred_swap_fails(): void
    {
        self::assertSame(Command::FAILURE, (new PendingBinarySwapCommitter($this->failingSwap()))->commit(new BufferedOutput()));
    }

    public function test_it_reports_why_the_deferred_swap_failed(): void
    {
        $bufferedOutput = new BufferedOutput();

        (new PendingBinarySwapCommitter($this->failingSwap()))->commit($bufferedOutput);

        self::assertStringContainsString('Failed to replace the binary at "/usr/local/bin/symfony-security-auditor": rename refused', $bufferedOutput->fetch());
    }

    public function test_it_says_the_previous_version_is_still_installed_when_the_swap_fails(): void
    {
        $bufferedOutput = new BufferedOutput();

        (new PendingBinarySwapCommitter($this->failingSwap()))->commit($bufferedOutput);

        self::assertStringContainsString('The update was not applied: the previous version is still installed. Run "self-update" again once the cause is fixed.', $bufferedOutput->fetch());
    }

    public function test_it_succeeds_silently_once_the_swap_is_committed(): void
    {
        $swapped = false;
        $pendingBinarySwap = new PendingBinarySwap();
        $pendingBinarySwap->schedule(static function () use (&$swapped): void {
            $swapped = true;
        });
        $bufferedOutput = new BufferedOutput();

        $exitCode = (new PendingBinarySwapCommitter($pendingBinarySwap))->commit($bufferedOutput);

        self::assertTrue($swapped);
        self::assertSame([Command::SUCCESS, ''], [$exitCode, $bufferedOutput->fetch()]);
    }

    private function failingSwap(): PendingBinarySwap
    {
        $pendingBinarySwap = new PendingBinarySwap();
        $pendingBinarySwap->schedule(static function (): never {
            throw SelfUpdateFailedException::forFailedReplacement('/usr/local/bin/symfony-security-auditor', new IOException('rename refused'));
        });

        return $pendingBinarySwap;
    }
}
