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

use Psr\Log\NullLogger;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\LazyCommand;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigPlatformOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigScanOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\FilesystemUpdateCheckStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\GitHubBinaryAssetResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ModelsDevCatalogRefresher;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\NullPricingCatalogRefresher;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PendingBinarySwap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PricingCatalogRefresherInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ProcessReleaseClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\RunningBinaryLocator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdater;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ThrottledUpdateAvailabilityNotifier;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\EnvironmentDoctor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ProcessComposerAvailabilityChecker;
use VinceAmstoutz\SymfonySecurityAuditor\Command\SelfUpdateCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableAuditCommandException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneApplicationFactory
{
    private const string APPLICATION_NAME = 'symfony-security-auditor';

    private const string PROJECT_CONFIG_FILENAME = '.symfony-security-auditor.yaml';

    private const string UPDATE_CHECK_OPT_OUT_VARIABLE = 'SSA_NO_UPDATE_CHECK';

    public function __construct(
        private StandaloneConfigLoader $standaloneConfigLoader,
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private BridgeInstallerInterface $bridgeInstaller,
        private StandaloneContainerFactory $standaloneContainerFactory = new StandaloneContainerFactory(),
        private StandaloneConsoleCommandFactory $standaloneConsoleCommandFactory = new StandaloneConsoleCommandFactory(),
        private string $runningBinaryPath = '',
        private string $pathEnvironment = '',
        private ?UpdateAvailabilityConsoleListener $updateAvailabilityConsoleListener = null,
        private PendingBinarySwap $pendingBinarySwap = new PendingBinarySwap(),
    ) {}

    /**
     * The standalone entry point drains this on the way out, once the console
     * application can no longer autoload from the archive being replaced.
     */
    public function pendingBinarySwap(): PendingBinarySwap
    {
        return $this->pendingBinarySwap;
    }

    /**
     * @param array<string, string> $environment
     */
    public static function fromEnvironment(array $environment, ?string $runningBinaryPath = null): self
    {
        $xdgConfigPathResolver = self::resolverFromEnvironment($environment);
        $resolvedBinaryPath = $runningBinaryPath ?? '';
        $pathEnvironment = $environment['PATH'] ?? '';
        $pendingBinarySwap = new PendingBinarySwap();

        return new self(
            new StandaloneConfigLoader(
                $xdgConfigPathResolver,
                new StandalonePlatformConfigResolver($environment),
                self::projectConfigFile($environment),
            ),
            $xdgConfigPathResolver,
            new ComposerBridgeInstaller(ComposerBridgeInstaller::defaultProcessBuilder()),
            runningBinaryPath: $resolvedBinaryPath,
            pathEnvironment: $pathEnvironment,
            updateAvailabilityConsoleListener: self::updateAvailabilityConsoleListener(
                $xdgConfigPathResolver,
                $resolvedBinaryPath,
                $pathEnvironment,
                self::updateChecksDisabled($environment),
                $pendingBinarySwap,
            ),
            pendingBinarySwap: $pendingBinarySwap,
        );
    }

    /**
     * @param array<string, string> $environment
     */
    public static function updateChecksDisabled(array $environment): bool
    {
        return !\in_array($environment[self::UPDATE_CHECK_OPT_OUT_VARIABLE] ?? '', ['', '0'], true);
    }

    /**
     * `$PWD` is a shell export that is absent on Windows and in cron/CI
     * contexts; the process working directory is always available.
     *
     * @param array<string, string> $environment
     */
    public static function projectConfigFile(array $environment): ?string
    {
        $pwd = $environment['PWD'] ?? '';
        $workingDirectory = '' !== $pwd ? $pwd : self::processWorkingDirectory();

        return null !== $workingDirectory ? \sprintf('%s/%s', $workingDirectory, self::PROJECT_CONFIG_FILENAME) : null;
    }

    /**
     * @param array<string, string> $environment
     *
     * @throws UnresolvableConfigPathException
     */
    public static function bridgeAutoloadFile(array $environment): string
    {
        return \sprintf('%s/vendor/autoload.php', self::resolverFromEnvironment($environment)->dataDir());
    }

    public function create(): StandaloneApplication
    {
        $standaloneApplication = new StandaloneApplication(self::APPLICATION_NAME, (new ReportPackage())->version(), (new ReportPackage(ModelsDevPricingProvider::CATALOG_PACKAGE))->version());
        $standaloneApplication->addCommand($this->initCommand());
        $standaloneApplication->addCommand($this->selfUpdateCommand());
        $standaloneApplication->addCommand($this->doctorCommand());
        $standaloneApplication->addCommand($this->lazyAuditCommand($standaloneApplication));
        $this->registerUpdateAvailabilityNotice($standaloneApplication);

        return $standaloneApplication;
    }

    private static function processWorkingDirectory(): ?string
    {
        $workingDirectory = getcwd();

        return false !== $workingDirectory ? $workingDirectory : null;
    }

    /**
     * @param array<string, string> $environment
     */
    private static function resolverFromEnvironment(array $environment): XdgConfigPathResolver
    {
        return XdgConfigPathResolver::fromEnvironment($environment, \PHP_OS_FAMILY);
    }

    private function initCommand(): InitCommand
    {
        return new InitCommand(
            $this->xdgConfigPathResolver,
            new StandaloneConfigFactory(),
            new YamlStandaloneConfigWriter(),
            $this->bridgeInstaller,
        );
    }

    private function selfUpdateCommand(): SelfUpdateCommand
    {
        return new SelfUpdateCommand(
            self::selfUpdater($this->runningBinaryPath, $this->pathEnvironment, $this->pendingBinarySwap, self::pricingCatalogRefresher($this->xdgConfigPathResolver)),
            (new ReportPackage())->version(),
            self::updateCheckStore($this->xdgConfigPathResolver),
            new NativeClock(),
        );
    }

    private static function selfUpdater(string $runningBinaryPath, string $pathEnvironment, PendingBinarySwap $pendingBinarySwap, PricingCatalogRefresherInterface $pricingCatalogRefresher = new NullPricingCatalogRefresher()): SelfUpdater
    {
        return new SelfUpdater(
            new ProcessReleaseClient(ProcessReleaseClient::defaultProcessBuilder()),
            new GitHubBinaryAssetResolver(\PHP_OS_FAMILY, php_uname('m')),
            new RunningBinaryLocator('/proc/self/exe', $runningBinaryPath, pathEnvironment: $pathEnvironment),
            $pendingBinarySwap,
            pricingCatalogRefresher: $pricingCatalogRefresher,
        );
    }

    /**
     * `self-update` must keep working before "init" has ever run, so this
     * never routes through `StandaloneConfigLoader::load()` — it would throw
     * `MissingPlatformException` on a fresh install. A config file that is
     * present but broken (an unresolvable home directory, malformed YAML)
     * fails closed to skipping the refresh, same as `privacy.offline_only`
     * being enabled on purpose. A fresh install with no config file yet has
     * nothing to fail closed on, so it defaults to online.
     */
    public static function pricingCatalogRefresher(XdgConfigPathResolver $xdgConfigPathResolver): PricingCatalogRefresherInterface
    {
        if (self::offlineOnly($xdgConfigPathResolver)) {
            return new NullPricingCatalogRefresher();
        }

        try {
            $cacheDir = $xdgConfigPathResolver->cacheDir();
        } catch (UnresolvableConfigPathException) {
            return new NullPricingCatalogRefresher();
        }

        return new ModelsDevCatalogRefresher(
            new ProcessReleaseClient(ProcessReleaseClient::defaultProcessBuilder()),
            $cacheDir,
            new NullLogger(),
        );
    }

    private static function offlineOnly(XdgConfigPathResolver $xdgConfigPathResolver): bool
    {
        try {
            $configFile = $xdgConfigPathResolver->configFile();
        } catch (UnresolvableConfigPathException) {
            return true;
        }

        if (!is_file($configFile)) {
            return false;
        }

        try {
            $parsed = Yaml::parseFile($configFile);
        } catch (ParseException) {
            return true;
        }

        return \is_array($parsed) && StandaloneConfig::offlineOnlyIn($parsed);
    }

    private static function updateAvailabilityConsoleListener(
        XdgConfigPathResolver $xdgConfigPathResolver,
        string $runningBinaryPath,
        string $pathEnvironment,
        bool $disabled,
        PendingBinarySwap $pendingBinarySwap,
    ): UpdateAvailabilityConsoleListener {
        return new UpdateAvailabilityConsoleListener(
            new ThrottledUpdateAvailabilityNotifier(
                self::selfUpdater($runningBinaryPath, $pathEnvironment, $pendingBinarySwap),
                self::updateCheckStore($xdgConfigPathResolver),
                new NativeClock(),
            ),
            (new ReportPackage())->version(),
            $disabled,
        );
    }

    private static function updateCheckStore(XdgConfigPathResolver $xdgConfigPathResolver): FilesystemUpdateCheckStore
    {
        return new FilesystemUpdateCheckStore($xdgConfigPathResolver, new Filesystem(), new NullLogger());
    }

    private function registerUpdateAvailabilityNotice(Application $application): void
    {
        if (!$this->updateAvailabilityConsoleListener instanceof UpdateAvailabilityConsoleListener) {
            return;
        }

        $eventDispatcher = new EventDispatcher();
        $eventDispatcher->addListener(ConsoleEvents::TERMINATE, $this->updateAvailabilityConsoleListener);

        $application->setDispatcher($eventDispatcher);
    }

    private function doctorCommand(): DoctorCommand
    {
        return new DoctorCommand(
            new EnvironmentDoctor(
                $this->standaloneConfigLoader,
                $this->xdgConfigPathResolver,
                new ProcessComposerAvailabilityChecker(ProcessComposerAvailabilityChecker::defaultProcessBuilder()),
                new StandaloneAuditPreflight(
                    $this->standaloneConfigLoader,
                    $this->xdgConfigPathResolver,
                    $this->standaloneContainerFactory,
                    $this->standaloneConsoleCommandFactory,
                ),
                new ModelsDevPricingProvider(new NullLogger(), $this->refreshedCatalogPath()),
            ),
        );
    }

    /**
     * Where a refreshed pricing catalog lands. `doctor` builds its provider
     * with the same override the audit container passes, so the two never
     * disagree about which catalog file the run prices from.
     */
    private function refreshedCatalogPath(): ?string
    {
        try {
            return \sprintf('%s/%s', $this->xdgConfigPathResolver->cacheDir(), ModelsDevPricingProvider::CATALOG_FILENAME);
        } catch (UnresolvableConfigPathException) {
            return null;
        }
    }

    private function lazyAuditCommand(StandaloneApplication $standaloneApplication): LazyCommand
    {
        return new LazyCommand(
            AuditCommand::NAME,
            [AuditCommand::ALIAS],
            AuditCommand::DESCRIPTION,
            false,
            fn (): Command => $this->loadAuditCommand($standaloneApplication->needsProviderCredentials()),
        );
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     * @throws MalformedProjectConfigException
     * @throws NonLocalPlatformEndpointException
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     */
    private function loadAuditCommand(bool $credentialsRequired): Command
    {
        return $this->standaloneConsoleCommandFactory->create($this->buildContainer($credentialsRequired));
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws MalformedProjectConfigException
     * @throws NonLocalPlatformEndpointException
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     */
    private function buildContainer(bool $credentialsRequired): ContainerBuilder
    {
        return $this->standaloneContainerFactory->create(
            $this->standaloneConfigLoader->load($credentialsRequired),
            $this->xdgConfigPathResolver->cacheDir(),
        );
    }
}
