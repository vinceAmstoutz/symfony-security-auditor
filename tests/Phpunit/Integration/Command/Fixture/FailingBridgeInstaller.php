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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;

/**
 * Test fake — fails every bridge installation, the way a network or composer
 * outage would.
 *
 * @internal scoped to InitCommandTest
 */
final class FailingBridgeInstaller implements BridgeInstallerInterface
{
    /**
     * @throws BridgeInstallationFailedException
     */
    #[Override]
    public function install(string $provider, string $targetDirectory): void
    {
        throw BridgeInstallationFailedException::forFailedProcess($provider, 'simulated outage');
    }
}
