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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\FilesystemUpdateCheckStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\GitHubBinaryAssetResolver;
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
    ) {}

    /**
     * @param array<string, string> $environment
     */
    public static function fromEnvironment(array $environment, ?string $runningBinaryPath = null): self
    {
        $xdgConfigPathResolver = self::resolverFromEnvironment($environment);
        $resolvedBinaryPath = $runningBinaryPath ?? '';
        $pathEnvironment = $environment['PATH'] ?? '';

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
            ),
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

    public function create(): Application
    {
        $application = new Application(self::APPLICATION_NAME, (new ReportPackage())->version());
        $application->addCommand($this->initCommand());
        $application->addCommand($this->selfUpdateCommand());
        $application->addCommand($this->doctorCommand());
        $application->addCommand($this->lazyAuditCommand());
        $this->registerUpdateAvailabilityNotice($application);

        return $application;
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
            self::selfUpdater($this->runningBinaryPath, $this->pathEnvironment),
            (new ReportPackage())->version(),
        );
    }

    private static function selfUpdater(string $runningBinaryPath, string $pathEnvironment): SelfUpdater
    {
        return new SelfUpdater(
            new ProcessReleaseClient(ProcessReleaseClient::defaultProcessBuilder()),
            new GitHubBinaryAssetResolver(\PHP_OS_FAMILY, php_uname('m')),
            new RunningBinaryLocator('/proc/self/exe', $runningBinaryPath, pathEnvironment: $pathEnvironment),
        );
    }

    private static function updateAvailabilityConsoleListener(
        XdgConfigPathResolver $xdgConfigPathResolver,
        string $runningBinaryPath,
        string $pathEnvironment,
        bool $disabled,
    ): UpdateAvailabilityConsoleListener {
        return new UpdateAvailabilityConsoleListener(
            new ThrottledUpdateAvailabilityNotifier(
                self::selfUpdater($runningBinaryPath, $pathEnvironment),
                new FilesystemUpdateCheckStore($xdgConfigPathResolver, new Filesystem(), new NullLogger()),
                new NativeClock(),
            ),
            (new ReportPackage())->version(),
            $disabled,
        );
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
            ),
        );
    }

    private function lazyAuditCommand(): LazyCommand
    {
        return new LazyCommand(
            AuditCommand::NAME,
            [AuditCommand::ALIAS],
            AuditCommand::DESCRIPTION,
            false,
            $this->loadAuditCommand(...),
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
     */
    private function loadAuditCommand(): Command
    {
        return $this->standaloneConsoleCommandFactory->create($this->buildContainer());
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws MalformedProjectConfigException
     */
    private function buildContainer(): ContainerBuilder
    {
        return $this->standaloneContainerFactory->create(
            $this->standaloneConfigLoader->load(),
            $this->xdgConfigPathResolver->cacheDir(),
        );
    }
}
