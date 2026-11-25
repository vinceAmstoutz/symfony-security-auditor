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

use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;

/**
 * Runs this application as the Composer it bundles, on its own PHP, so the
 * host needs neither.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class EmbeddedComposer
{
    private const string COMPOSER_VARIABLE = 'SYMFONY_SECURITY_AUDITOR_COMPOSER';

    public function __construct(
        private SelfInvocation $selfInvocation,
        private ComposerPhar $composerPhar,
    ) {}

    /**
     * @return ?self null when this build bundles no `composer.phar`, as when it runs from source
     */
    public static function bundled(SelfInvocation $selfInvocation, ComposerPhar $composerPhar): ?self
    {
        return $composerPhar->isBundled() ? new self($selfInvocation, $composerPhar) : null;
    }

    /**
     * @param string                $composerDirectory where Composer is unpacked
     * @param list<string>          $arguments
     * @param array<string, string> $environment       variables set besides the inherited ones
     *
     * @throws BridgeInstallationFailedException
     */
    public function process(string $composerDirectory, array $arguments, array $environment = []): Process
    {
        return new Process(
            [...$this->selfInvocation->command(), ...$arguments],
            env: [...$environment, self::COMPOSER_VARIABLE => $this->composerPhar->in($composerDirectory)],
        );
    }
}
