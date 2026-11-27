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
 * Installs `symfony/ai-<slug>-platform` bridges with `composer require`, the
 * provider being a `symfony/ai` platform config key such as `openai`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
        'claudecode' => 'claude-code',
    ];

    private const string MANIFEST_FILENAME = 'composer.json';

    private const string PLATFORM_PACKAGE = 'symfony/ai-platform';

    private const string BRIDGE_PACKAGE_PATTERN = '#^symfony/ai-.+-platform$#';

    /**
     * @param Closure(string, ?string, string, string...): Process $processBuilder     builds the `composer require` process from the bridge package, the `symfony/ai-platform` pin, the target directory and the further bridge packages; self::embeddedProcessBuilder() in production
     * @param string                                               $platformPhpVersion the PHP version the bridge tree resolves for: the binary's own, not the host's
     * @param ?string                                              $aiPlatformPin      the `symfony/ai-platform` release the bridge tree is held to, the bundled one ({@see BundledAiPlatformVersion}); null writes no pin
     */
    public function __construct(
        private Closure $processBuilder,
        private Filesystem $filesystem = new Filesystem(),
        private string $platformPhpVersion = \PHP_VERSION,
        private ?string $aiPlatformPin = null,
    ) {}

    /**
     * Runs this binary as Composer on its own PHP, so the host needs neither.
     * An installed `symfony/ai-platform` of another release moves to the pin
     * with what the bridges pulled in.
     *
     * @return Closure(string, ?string, string, string...): Process
     */
    public static function embeddedProcessBuilder(SelfInvocation $selfInvocation, ComposerPhar $composerPhar): Closure
    {
        $embeddedComposer = new EmbeddedComposer($selfInvocation, $composerPhar);

        return static function (string $package, ?string $aiPlatformPin, string $targetDirectory, string ...$morePackages) use ($embeddedComposer): Process {
            $composerDirectory = \sprintf('%s/.composer', $targetDirectory);
            $process = $embeddedComposer->process($composerDirectory, self::requireArguments($package, $aiPlatformPin, $targetDirectory, ...$morePackages), [
                'COMPOSER_HOME' => \sprintf('%s/home', $composerDirectory),
                'COMPOSER_CACHE_DIR' => \sprintf('%s/cache', $composerDirectory),
            ]);
            $process->setTimeout(null);

            return $process;
        };
    }

    /**
     * @return list<string>
     */
    private static function requireArguments(string $package, ?string $aiPlatformPin, string $targetDirectory, string ...$morePackages): array
    {
        $packages = [$package, ...array_values($morePackages)];
        $required = null === $aiPlatformPin ? $packages : [...$packages, \sprintf('%s:%s', self::PLATFORM_PACKAGE, $aiPlatformPin)];

        return ['require', ...$required, '--with-dependencies', \sprintf('--working-dir=%s', $targetDirectory), '--no-interaction'];
    }

    /**
     * Requires every bridge in one `composer require`, those the manifest
     * already requires included, so none stays locked to another
     * `symfony/ai-platform` release than the pin.
     *
     * @throws BridgeInstallationFailedException
     */
    #[Override]
    public function install(string $provider, string $targetDirectory, string ...$moreProviders): void
    {
        $requiredBridges = $this->ensureComposerProject($targetDirectory);

        $package = self::packageFor($provider);
        $morePackages = array_diff(array_unique([...array_map(self::packageFor(...), $moreProviders), ...$requiredBridges]), [$package]);
        $process = ($this->processBuilder)($package, $this->aiPlatformPin, $targetDirectory, ...$morePackages);
        $packageNames = implode('", "', [$package, ...$morePackages]);

        try {
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw BridgeInstallationFailedException::forUnavailableComposer($packageNames, $exception);
        }

        if (!$process->isSuccessful()) {
            throw BridgeInstallationFailedException::forFailedProcess($packageNames, '' !== $process->getErrorOutput() ? $process->getErrorOutput() : $process->getOutput());
        }
    }

    /**
     * Returns the bridge package of the provider's platform, whatever instance
     * it names.
     */
    public static function packageFor(string $provider): string
    {
        $platform = ProviderKey::of($provider)->platform;

        return \sprintf(self::PACKAGE_TEMPLATE, self::PACKAGE_SLUG_OVERRIDES[$platform] ?? $platform);
    }

    /**
     * The platform a bridge package's slug stands for: the reverse of
     * {@see packageFor()}.
     */
    public static function platformForSlug(string $slug): string
    {
        return array_flip(self::PACKAGE_SLUG_OVERRIDES)[$slug] ?? $slug;
    }

    /**
     * @return list<string> the bridge packages the manifest already required
     *
     * @throws BridgeInstallationFailedException
     */
    private function ensureComposerProject(string $targetDirectory): array
    {
        $manifest = \sprintf('%s/%s', $targetDirectory, self::MANIFEST_FILENAME);
        $this->assertSafeToWrite($manifest, $targetDirectory);

        $existingManifest = $this->existingManifest($manifest);
        $requiredBridges = $this->requiredBridges($existingManifest);
        $contents = $this->pinnedManifest($existingManifest);

        try {
            $this->filesystem->dumpFile($manifest, $contents);
        } catch (IOException $ioException) {
            throw BridgeInstallationFailedException::forManifestWriteFailure($targetDirectory, $ioException);
        }

        return $requiredBridges;
    }

    /**
     * @return list<string>
     */
    private function requiredBridges(stdClass $manifest): array
    {
        $require = ($manifest->require ?? null) instanceof stdClass ? get_object_vars($manifest->require) : [];

        $bridges = [];
        foreach (array_keys($require) as $package) {
            if (\is_string($package) && 1 === preg_match(self::BRIDGE_PACKAGE_PATTERN, $package)) {
                $bridges[] = $package;
            }
        }

        return $bridges;
    }

    /**
     * Decodes to objects, so an empty JSON object such as
     * `config.allow-plugins: {}` is written back as one, as Composer requires.
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
     * Pins `config.platform.php` to the PHP that loads the tree and
     * `symfony/ai-platform` to the bundled release on every install, keeping
     * every other key.
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
     * Refuses a symlinked manifest or target directory, a dangling one
     * included, which `dumpFile()` would write through.
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
