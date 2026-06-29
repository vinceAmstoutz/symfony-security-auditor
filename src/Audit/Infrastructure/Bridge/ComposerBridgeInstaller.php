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

use Closure;
use Override;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;

/**
 * Installs a `symfony/ai-<provider>-platform` bridge into a writable directory
 * via `composer require`. The same convention applies to every provider, so
 * there is no per-provider branching.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerBridgeInstaller implements BridgeInstallerInterface
{
    public const int DEFAULT_TIMEOUT_SECONDS = 300;

    private const string PACKAGE_TEMPLATE = 'symfony/ai-%s-platform';

    private const string MANIFEST_FILENAME = 'composer.json';

    private const string EMPTY_MANIFEST = "{}\n";

    /**
     * @param Closure(string, string): Process $processBuilder the composer-require command builder (use self::defaultProcessBuilder() in production); tests inject a stub
     */
    public function __construct(
        private Closure $processBuilder,
        private Filesystem $filesystem = new Filesystem(),
        private int $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
    ) {}

    /**
     * @return Closure(string, string): Process
     */
    public static function defaultProcessBuilder(): Closure
    {
        return static fn (string $package, string $targetDirectory): Process => new Process(
            ['composer', 'require', $package, \sprintf('--working-dir=%s', $targetDirectory), '--no-interaction'],
        );
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    #[Override]
    public function install(string $provider, string $targetDirectory): void
    {
        $this->ensureComposerProject($targetDirectory);

        $package = \sprintf(self::PACKAGE_TEMPLATE, $provider);
        $process = ($this->processBuilder)($package, $targetDirectory);

        try {
            $process->setTimeout((float) $this->timeoutSeconds);
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw BridgeInstallationFailedException::forUnavailableComposer($package, $exception);
        }

        if (!$process->isSuccessful()) {
            throw BridgeInstallationFailedException::forFailedProcess($package, $process->getErrorOutput());
        }
    }

    private function ensureComposerProject(string $targetDirectory): void
    {
        $manifest = \sprintf('%s/%s', $targetDirectory, self::MANIFEST_FILENAME);
        if (!$this->filesystem->exists($manifest)) {
            $this->filesystem->dumpFile($manifest, self::EMPTY_MANIFEST);
        }
    }
}
