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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\RunningBinaryLocatorInterface;

/**
 * The command that starts this application again in a process of its own:
 * the standalone binary alone, or the PHP running it and its entry script.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SelfInvocation
{
    private const string STANDALONE_SAPI = 'micro';

    public function __construct(
        private RunningBinaryLocatorInterface $runningBinaryLocator,
        private string $scriptPath,
        private string $sapi = \PHP_SAPI,
        private string $phpBinary = \PHP_BINARY,
    ) {}

    /**
     * @return list<string>
     *
     * @throws BridgeInstallationFailedException
     */
    public function command(): array
    {
        if (self::STANDALONE_SAPI !== $this->sapi) {
            return [$this->phpBinary, $this->scriptPath];
        }

        try {
            return [$this->runningBinaryLocator->path()];
        } catch (SelfUpdateFailedException $selfUpdateFailedException) {
            throw BridgeInstallationFailedException::forUnlocatableBinary($selfUpdateFailedException);
        }
    }
}
