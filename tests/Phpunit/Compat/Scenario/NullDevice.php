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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use Override;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\Workspace;

/**
 * Creates the workspace's own discard device, `{null-device}`, for a process
 * that could otherwise write over the system's `/dev/null`; one that cannot
 * uses the system's.
 */
final readonly class NullDevice implements SetupActionInterface
{
    private const array NULL_DEVICE_NUMBERS = ['c', '1', '3'];

    #[Override]
    public function apply(Workspace $workspace): void
    {
        if (Workspace::canWriteSystemDevices()) {
            (new Process(['mknod', '-m', '666', $workspace->nullDevice(), ...self::NULL_DEVICE_NUMBERS]))->mustRun();
        }
    }
}
