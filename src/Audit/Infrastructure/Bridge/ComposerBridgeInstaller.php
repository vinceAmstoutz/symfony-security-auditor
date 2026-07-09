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
use Symfony\Component\Filesystem\Exception\IOException;
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
    private const string PACKAGE_TEMPLATE = 'symfony/ai-%s-platform';

    private const string MANIFEST_FILENAME = 'composer.json';

    private const string EMPTY_MANIFEST = "{}\n";

    /**
     * @param Closure(string, string): Process $processBuilder the composer-require command builder (use self::defaultProcessBuilder() in production); tests inject a stub
     */
    public function __construct(
        private Closure $processBuilder,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @return Closure(string, string): Process
     */
    public static function defaultProcessBuilder(): Closure
    {
        return static function (string $package, string $targetDirectory): Process {
            $process = new Process(['composer', 'require', $package, \sprintf('--working-dir=%s', $targetDirectory), '--no-interaction']);
            $process->setTimeout(null);

            return $process;
        };
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
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw BridgeInstallationFailedException::forUnavailableComposer($package, $exception);
        }

        if (!$process->isSuccessful()) {
            throw BridgeInstallationFailedException::forFailedProcess($package, $process->getErrorOutput());
        }
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    private function ensureComposerProject(string $targetDirectory): void
    {
        $manifest = \sprintf('%s/%s', $targetDirectory, self::MANIFEST_FILENAME);
        $this->assertSafeToWrite($manifest, $targetDirectory);

        if ($this->filesystem->exists($manifest)) {
            return;
        }

        try {
            $this->filesystem->dumpFile($manifest, self::EMPTY_MANIFEST);
        } catch (IOException $ioException) {
            throw BridgeInstallationFailedException::forManifestWriteFailure($targetDirectory, $ioException);
        }
    }

    /**
     * `Filesystem::exists()` follows a symlink, so a *dangling* one at the
     * manifest path reads as absent — skipping the "already exists" early
     * return — and `dumpFile()` then transparently writes through it to
     * wherever it points. Mirrors the guard already applied to the
     * filesystem attacker/reviewer/advisory caches, the standalone config
     * writer, and the report/baseline writers.
     *
     * @throws BridgeInstallationFailedException
     */
    private function assertSafeToWrite(string $manifest, string $targetDirectory): void
    {
        if (is_link($manifest) || is_link($targetDirectory)) {
            throw BridgeInstallationFailedException::forSymlinkedTargetDirectory($targetDirectory);
        }
    }
}
