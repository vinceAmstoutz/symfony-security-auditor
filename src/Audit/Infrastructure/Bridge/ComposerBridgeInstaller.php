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
use JsonException;
use Override;
use stdClass;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;
use UnexpectedValueException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;

/**
 * Installs a `symfony/ai-<slug>-platform` bridge into a writable directory via
 * `composer require`. The provider name is the `symfony/ai` platform *config*
 * key (`openai`, `deepseek`, …); a handful of packages spell that key with
 * hyphens (`symfony/ai-open-ai-platform` for the `openai` platform), so those
 * are mapped to their package slug before the package name is built. An
 * instance-scoped provider (`generic.my_gateway`) names one instance of a
 * platform, not a package of its own, so only the platform part selects the
 * bridge.
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
        'openrouter' => 'open-router',
        'deepseek' => 'deep-seek',
        'edenai' => 'eden-ai',
        'typesafe' => 'type-safe',
        'vertexai' => 'vertex-ai',
        'huggingface' => 'hugging-face',
        'elevenlabs' => 'eleven-labs',
        'amazeeai' => 'amazee-ai',
        'minimax' => 'mini-max',
        'lmstudio' => 'lm-studio',
        'dockermodelrunner' => 'docker-model-runner',
        'transformersphp' => 'transformers-php',
    ];

    private const string MANIFEST_FILENAME = 'composer.json';

    private const string PLATFORM_PACKAGE = 'symfony/ai-platform';

    /**
     * @param Closure(string, ?string, string, string...): Process $processBuilder     the composer-require command builder, given the bridge package, the `symfony/ai-platform` pin, the target directory and any further bridge package to require in the same run (use self::defaultProcessBuilder() in production); tests inject a stub
     * @param string                                               $platformPhpVersion the PHP version the bridge tree must resolve for — defaults to the running runtime (`PHP_VERSION`), which for the standalone binary is its own bundled PHP, not the host's
     * @param ?string                                              $aiPlatformPin      the `symfony/ai-platform` release the bridge tree is held to — the one this binary bundles ({@see BundledAiPlatformVersion}), so a newer release the bridge would otherwise pull in cannot shadow the bundled classes; null writes no pin
     */
    public function __construct(
        private Closure $processBuilder,
        private Filesystem $filesystem = new Filesystem(),
        private string $platformPhpVersion = \PHP_VERSION,
        private ?string $aiPlatformPin = null,
    ) {}

    /**
     * The pin is named on the command line as well as in the manifest:
     * composer then moves an already installed newer `symfony/ai-platform`
     * back to it, where the manifest pin alone would only report a conflict.
     *
     * @return Closure(string, ?string, string, string...): Process
     */
    public static function defaultProcessBuilder(): Closure
    {
        return static function (string $package, ?string $aiPlatformPin, string $targetDirectory, string ...$morePackages): Process {
            $packages = [$package, ...$morePackages];
            $required = null === $aiPlatformPin ? $packages : [...$packages, \sprintf('%s:%s', self::PLATFORM_PACKAGE, $aiPlatformPin)];
            $process = new Process(['composer', 'require', ...$required, \sprintf('--working-dir=%s', $targetDirectory), '--no-interaction']);
            $process->setTimeout(null);

            return $process;
        };
    }

    /**
     * Every bridge goes into one `composer require`, so a platform that also
     * needs another's bridge resolves the tree once rather than twice.
     *
     * @throws BridgeInstallationFailedException
     */
    #[Override]
    public function install(string $provider, string $targetDirectory, string ...$moreProviders): void
    {
        $this->ensureComposerProject($targetDirectory);

        $package = self::packageFor($provider);
        $morePackages = array_map(self::packageFor(...), $moreProviders);
        $process = ($this->processBuilder)($package, $this->aiPlatformPin, $targetDirectory, ...$morePackages);
        $packageNames = implode('", "', [$package, ...$morePackages]);

        try {
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw BridgeInstallationFailedException::forUnavailableComposer($packageNames, $exception);
        }

        if (!$process->isSuccessful()) {
            throw BridgeInstallationFailedException::forFailedProcess($packageNames, $process->getErrorOutput());
        }
    }

    /**
     * The bridge package a provider selects. Only the platform half names a
     * bridge: an instance is a connection of that platform, not a package.
     */
    public static function packageFor(string $provider): string
    {
        $platform = ProviderKey::of($provider)->platform;

        return \sprintf(self::PACKAGE_TEMPLATE, self::PACKAGE_SLUG_OVERRIDES[$platform] ?? $platform);
    }

    /**
     * The platform a bridge package's slug stands for — the reverse of
     * {@see packageFor()}.
     */
    public static function platformForSlug(string $slug): string
    {
        return array_flip(self::PACKAGE_SLUG_OVERRIDES)[$slug] ?? $slug;
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    private function ensureComposerProject(string $targetDirectory): void
    {
        $manifest = \sprintf('%s/%s', $targetDirectory, self::MANIFEST_FILENAME);
        $this->assertSafeToWrite($manifest, $targetDirectory);

        $contents = $this->pinnedManifest($this->existingManifest($manifest));

        try {
            $this->filesystem->dumpFile($manifest, $contents);
        } catch (IOException $ioException) {
            throw BridgeInstallationFailedException::forManifestWriteFailure($targetDirectory, $ioException);
        }
    }

    /**
     * Decoded as objects, not associative arrays, so an empty JSON object such
     * as `config.allow-plugins: {}` survives the round-trip: `json_decode(...,
     * true)` turns `{}` into `[]`, which `json_encode` writes back as `[]`, and
     * Composer then rejects the manifest ("Array value found, but an object is
     * required") — bricking every later `init` on the tree.
     *
     * @throws BridgeInstallationFailedException
     */
    private function existingManifest(string $manifest): stdClass
    {
        if (!$this->filesystem->exists($manifest)) {
            return new stdClass();
        }

        try {
            $decoded = json_decode($this->filesystem->readFile($manifest), false, flags: \JSON_THROW_ON_ERROR);
        } catch (IOException|JsonException $failure) {
            throw BridgeInstallationFailedException::forUnreadableManifest($manifest, $failure);
        }

        return $decoded instanceof stdClass ? $decoded : throw BridgeInstallationFailedException::forUnreadableManifest($manifest, new UnexpectedValueException('The manifest is not a JSON object.'));
    }

    /**
     * Pins `config.platform.php` so `composer require` resolves the bridge for
     * the runtime that will load it — the standalone binary bundles its own
     * PHP; resolved against the host's, the tree aborts in the binary's
     * `vendor/composer/platform_check.php` — and `symfony/ai-platform` to the
     * release the binary bundles. Both pins are refreshed on every install, so
     * a manifest written by an older release is corrected rather than kept
     * forever; every other key is preserved.
     */
    private function pinnedManifest(stdClass $manifest): string
    {
        $config = ($manifest->config ?? null) instanceof stdClass ? $manifest->config : new stdClass();
        $platform = ($config->platform ?? null) instanceof stdClass ? $config->platform : new stdClass();
        $platform->php = $this->platformPhpVersion;

        $config->platform = $platform;
        $manifest->config = $config;

        if (null !== $this->aiPlatformPin) {
            $require = ($manifest->require ?? null) instanceof stdClass ? (array) $manifest->require : [];
            $require[self::PLATFORM_PACKAGE] = $this->aiPlatformPin;
            $manifest->require = $require;
        }

        return \sprintf("%s\n", json_encode($manifest, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR));
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
