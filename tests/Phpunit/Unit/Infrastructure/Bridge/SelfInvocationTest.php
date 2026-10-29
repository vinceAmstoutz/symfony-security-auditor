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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Bridge;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\SelfInvocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\RunningBinaryLocatorInterface;

final class SelfInvocationTest extends TestCase
{
    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_the_standalone_binary_is_started_on_its_own(): void
    {
        $runningBinaryLocator = self::createStub(RunningBinaryLocatorInterface::class);
        $runningBinaryLocator->method('path')->willReturn('/opt/symfony-security-auditor/symfony-security-auditor');

        $selfInvocation = new SelfInvocation($runningBinaryLocator, 'symfony-security-auditor', 'micro', 'symfony-security-auditor');

        self::assertSame(['/opt/symfony-security-auditor/symfony-security-auditor'], $selfInvocation->command());
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_a_php_run_is_started_again_through_the_same_php_and_entry_script(): void
    {
        $selfInvocation = new SelfInvocation(self::createStub(RunningBinaryLocatorInterface::class), '/app/bin/symfony-security-auditor', 'cli', '/usr/bin/php8.3');

        self::assertSame(['/usr/bin/php8.3', '/app/bin/symfony-security-auditor'], $selfInvocation->command());
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_a_standalone_binary_that_cannot_be_located_fails_the_bridge_installation(): void
    {
        $runningBinaryLocator = self::createStub(RunningBinaryLocatorInterface::class);
        $runningBinaryLocator->method('path')->willThrowException(SelfUpdateFailedException::forUndeterminedBinaryPath());

        $this->expectException(BridgeInstallationFailedException::class);

        (new SelfInvocation($runningBinaryLocator, 'symfony-security-auditor', 'micro'))->command();
    }
}
