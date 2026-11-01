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

final class SelfInvocationTest extends TestCase
{
    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_the_standalone_binary_is_started_on_its_own(): void
    {
        $selfInvocation = new SelfInvocation('C:\Users\me\bin\symfony-security-auditor.exe', 'micro', '');

        self::assertSame(['C:\Users\me\bin\symfony-security-auditor.exe'], $selfInvocation->command());
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_a_php_run_is_started_again_through_the_same_php_and_entry_script(): void
    {
        $selfInvocation = new SelfInvocation('/app/bin/symfony-security-auditor', 'cli', '/usr/bin/php8.3');

        self::assertSame(['/usr/bin/php8.3', '/app/bin/symfony-security-auditor'], $selfInvocation->command());
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_a_standalone_binary_that_does_not_know_its_own_path_fails_the_bridge_installation(): void
    {
        $this->expectException(BridgeInstallationFailedException::class);

        (new SelfInvocation('', 'micro', ''))->command();
    }
}
