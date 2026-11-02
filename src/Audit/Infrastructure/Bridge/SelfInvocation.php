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

/**
 * The command that starts this application again in a process of its own:
 * the standalone binary alone, by the absolute path phpmicro's
 * `micro_get_self_filename()` gives on every platform, or the PHP running
 * the entry script and that script.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SelfInvocation
{
    private const string STANDALONE_SAPI = 'micro';

    public function __construct(
        private string $runningBinaryPath,
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
            return [$this->phpBinary, $this->runningBinaryPath];
        }

        if ('' === $this->runningBinaryPath) {
            throw BridgeInstallationFailedException::forUnlocatableBinary();
        }

        return [$this->runningBinaryPath];
    }
}
