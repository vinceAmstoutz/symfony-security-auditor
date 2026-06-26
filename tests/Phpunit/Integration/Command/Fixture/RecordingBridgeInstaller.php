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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;

/**
 * Test fake — records the bridge installations requested by the command.
 *
 * @internal scoped to InitCommandTest
 */
final class RecordingBridgeInstaller implements BridgeInstallerInterface
{
    /**
     * @var list<array{string, string}>
     */
    public array $installations = [];

    public function install(string $provider, string $targetDirectory): void
    {
        $this->installations[] = [$provider, $targetDirectory];
    }
}
