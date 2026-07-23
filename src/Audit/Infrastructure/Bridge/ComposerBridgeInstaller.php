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
 * Installs a `symfony/ai-<slug>-platform` bridge into a writable directory via
 * `composer require`. The provider name is the `symfony/ai` platform *config*
 * key (`openai`, `deepseek`, …); a handful of packages spell that key with
 * hyphens (`symfony/ai-open-ai-platform` for the `openai` platform), so those
 * are mapped to their package slug before the package name is built.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerBridgeInstaller implements BridgeInstallerInterface
{
    private const string PACKAGE_TEMPLATE = 'symfony/ai-%s-platform';

    /**
     * Platform config keys whose bridge package slug is hyphenated.
     *
     * @var array<string, string>
     */
    public const array PACKAGE_SLUG_OVERRIDES = [
        'openai' => 'open-ai',
        'openresponses' => 'open-responses',
        'deepseek' => 'deep-seek',
        'vertexai' => 'vertex-ai',
        'huggingface' => 'hugging-face',
        'elevenlabs' => 'eleven-labs',
        'amazeeai' => 'amazee-ai',
    ];

    private const string MANIFEST_FILENAME = 'composer.json';

    /**
     * @param Closure(string, string): Process $processBuilder     the composer-require command builder (use self::defaultProcessBuilder() in production); tests inject a stub
     * @param string                           $platformPhpVersion the PHP version the bridge tree must resolve for — defaults to the running runtime (`PHP_VERSION`), which for the standalone binary is its own bundled PHP, not the host's
     */
    public function __construct(
        private Closure $processBuilder,
        private Filesystem $filesystem = new Filesystem(),
        private string $platformPhpVersion = \PHP_VERSION,
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

        $package = \sprintf(self::PACKAGE_TEMPLATE, self::PACKAGE_SLUG_OVERRIDES[$provider] ?? $provider);
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
            $this->filesystem->dumpFile($manifest, $this->manifestContents());
        } catch (IOException $ioException) {
            throw BridgeInstallationFailedException::forManifestWriteFailure($targetDirectory, $ioException);
        }
    }

    /**
     * Pins `config.platform.php` so `composer require` resolves the bridge for
     * the runtime that will load it. The standalone binary bundles its own PHP;
     * without this, `init` resolves against the host's (possibly newer) PHP and
     * the binary then aborts in `vendor/composer/platform_check.php`.
     */
    private function manifestContents(): string
    {
        return \sprintf(
            "%s\n",
            json_encode(
                ['config' => ['platform' => ['php' => $this->platformPhpVersion]]],
                \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR,
            ),
        );
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
