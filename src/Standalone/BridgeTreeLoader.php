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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeTree;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\StaleBridgeTreeException;

/**
 * Registers the autoloader of the provider bridges `init` installed, ahead of
 * the binary's own, unless the tree holds another `symfony/ai-platform` than
 * the bundled one: that tree stays unloaded and the commands needing it say
 * why. A tree whose platform check refuses this PHP is reported rather than
 * fatal, so the command still runs — `init` included, which rebuilds it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BridgeTreeLoader
{
    private const string UNLOADABLE = 'The provider bridge under "%s" cannot be loaded by this binary: %s%sRun "init --provider=<platform> --force" to rebuild it for the bundled PHP.';

    /**
     * @return ?string the warning to print when the tree is there but cannot be loaded
     */
    public function load(BridgeTree $bridgeTree): ?string
    {
        if (!$bridgeTree->isInstalled()) {
            return null;
        }

        try {
            $bridgeTree->assertLoadable(null);
        } catch (StaleBridgeTreeException) {
            return null;
        }

        return $this->registerAutoloader($bridgeTree);
    }

    private function registerAutoloader(BridgeTree $bridgeTree): ?string
    {
        set_error_handler(new PlatformCheckErrorConverter(), \E_USER_ERROR | \E_DEPRECATED);

        try {
            require_once $bridgeTree->autoloadFile();
        } catch (RuntimeException $runtimeException) {
            return \sprintf(self::UNLOADABLE, $bridgeTree->directory, $runtimeException->getMessage(), \PHP_EOL);
        } finally {
            restore_error_handler();
        }

        return null;
    }
}
