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

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\LazyCommand;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommand;
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

    public function __construct(
        private StandaloneConfigLoader $standaloneConfigLoader,
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneContainerFactory $standaloneContainerFactory = new StandaloneContainerFactory(),
        private StandaloneConsoleCommandFactory $standaloneConsoleCommandFactory = new StandaloneConsoleCommandFactory(),
    ) {}

    /**
     * @param array<string, string> $environment
     */
    public static function fromEnvironment(array $environment): self
    {
        $xdgConfigPathResolver = self::resolverFromEnvironment($environment);

        return new self(
            new StandaloneConfigLoader(
                $xdgConfigPathResolver,
                new StandalonePlatformConfigResolver($environment),
                self::projectConfigFile($environment),
            ),
            $xdgConfigPathResolver,
        );
    }

    /**
     * @param array<string, string> $environment
     */
    public static function projectConfigFile(array $environment): ?string
    {
        $workingDirectory = $environment['PWD'] ?? null;

        return null !== $workingDirectory ? $workingDirectory.'/'.self::PROJECT_CONFIG_FILENAME : null;
    }

    /**
     * @param array<string, string> $environment
     *
     * @throws UnresolvableConfigPathException
     */
    public static function bridgeAutoloadFile(array $environment): string
    {
        return self::resolverFromEnvironment($environment)->dataDir().'/vendor/autoload.php';
    }

    public function create(): Application
    {
        $application = new Application(self::APPLICATION_NAME);
        $application->addCommand($this->initCommand());
        $application->addCommand($this->lazyAuditCommand());

        return $application;
    }

    /**
     * @param array<string, string> $environment
     */
    private static function resolverFromEnvironment(array $environment): XdgConfigPathResolver
    {
        return new XdgConfigPathResolver(
            $environment['XDG_CONFIG_HOME'] ?? null,
            $environment['XDG_CACHE_HOME'] ?? null,
            $environment['HOME'] ?? null,
            $environment['XDG_DATA_HOME'] ?? null,
        );
    }

    private function initCommand(): InitCommand
    {
        return new InitCommand(
            $this->xdgConfigPathResolver,
            new StandaloneConfigFactory(),
            new YamlStandaloneConfigWriter(),
            new ComposerBridgeInstaller(),
        );
    }

    private function lazyAuditCommand(): LazyCommand
    {
        return new LazyCommand(
            AuditCommand::NAME,
            [StandaloneConsoleCommandFactory::AUDIT_ALIAS],
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
     */
    private function buildContainer(): ContainerBuilder
    {
        return $this->standaloneContainerFactory->create(
            $this->standaloneConfigLoader->load(),
            $this->xdgConfigPathResolver->cacheDir(),
        );
    }
}
