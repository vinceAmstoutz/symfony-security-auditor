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

use Psr\Clock\ClockInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\AI\AiBundle\AiBundle;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OfflineOnlyPlatformGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PricingPlatformPass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConsoleBannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\CredentialConsoleBanner;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServeCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\NullConsoleBanner;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\ProviderBridgeException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneContainerFactory
{
    private const string CONFIG_NOTICES_PARAMETER = 'symfony_security_auditor.config_notices';

    private const string PROJECT_CONFIG_NOTICE = 'Project config %s is layered over your user config: the audited repository may tune the audit through it (paths, profile, models, a tighter budget), never the platform and its credentials, the cache, privacy, custom skills, secret scrubbing, custom risk patterns or imported SARIF.';

    private const string PLATFORM_TAG = 'ai.platform';

    private const string PLATFORM_SERVICE_PREFIX = 'ai.platform.';

    public function __construct(
        private BundleExtensionLoader $bundleExtensionLoader = new BundleExtensionLoader(),
        private OfflineOnlyPlatformGuard $offlineOnlyPlatformGuard = new OfflineOnlyPlatformGuard(),
    ) {}

    /**
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    public function create(StandaloneConfig $standaloneConfig, string $cacheDir): ContainerBuilder
    {
        if ($standaloneConfig->offlineOnly()) {
            $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal($standaloneConfig->platform);
        }

        $workingDirectory = getcwd();

        $containerBuilder = new ContainerBuilder(new EnvPlaceholderParameterBag([
            'kernel.cache_dir' => $cacheDir,
            'kernel.build_dir' => $cacheDir,
            'kernel.project_dir' => false !== $workingDirectory ? $workingDirectory : $cacheDir,
            'kernel.environment' => 'prod',
            'kernel.debug' => false,
        ]));

        $containerBuilder->register('event_dispatcher', EventDispatcher::class)->setPublic(true);
        $containerBuilder->register('logger', NullLogger::class);
        $containerBuilder->register(ClockInterface::class, NativeClock::class);
        $containerBuilder->register('http_client', HttpClientInterface::class)
            ->setFactory([HttpClient::class, 'create'])
            ->setArguments([['timeout' => $standaloneConfig->httpTimeout, 'max_duration' => 0]]);

        try {
            $this->bundleExtensionLoader->load(new AiBundle(), $standaloneConfig->platform->toAiConfig(), $containerBuilder);
        } catch (RuntimeException $runtimeException) {
            throw ProviderBridgeException::forBundleFailure($runtimeException) ?? $runtimeException;
        }

        $this->bundleExtensionLoader->load(new SymfonySecurityAuditorBundle(), $standaloneConfig->auditConfig, $containerBuilder);

        $this->announceProjectConfig($containerBuilder, $standaloneConfig->projectConfigFile);
        $this->registerAuditHeaderBanner($containerBuilder, $standaloneConfig->platform);

        $this->selectActivePlatform($containerBuilder, $standaloneConfig->platform);

        $containerBuilder->getDefinition(AuditCommand::class)->setPublic(true);
        $containerBuilder->getDefinition(McpServeCommand::class)->setPublic(true);
        $containerBuilder->addCompilerPass(new PricingPlatformPass(PlatformInterface::class));
        $containerBuilder->compile(true);

        return $containerBuilder;
    }

    /**
     * The audited repository may tune the run through its own config file, so
     * the audit header says which file was layered in: a stricter `fail_on` or
     * another model coming from the checkout rather than from the user's own
     * file would otherwise be silent.
     */
    private function announceProjectConfig(ContainerBuilder $containerBuilder, ?string $projectConfigFile): void
    {
        if (null === $projectConfigFile) {
            return;
        }

        $notices = $containerBuilder->getParameter(self::CONFIG_NOTICES_PARAMETER);

        $containerBuilder->setParameter(self::CONFIG_NOTICES_PARAMETER, [
            ...(\is_array($notices) ? $notices : []),
            \sprintf(self::PROJECT_CONFIG_NOTICE, ContainerParameterSyntax::escape($projectConfigFile)),
        ]);
    }

    /**
     * The product banner is already on screen by the time a command runs, so
     * the audit header carries the credential the run will spend instead of
     * repeating it — named by its masked preview, never printed.
     */
    private function registerAuditHeaderBanner(ContainerBuilder $containerBuilder, StandalonePlatformConfig $standalonePlatformConfig): void
    {
        $credentialIdentity = $standalonePlatformConfig->credentialIdentity();

        if (!$credentialIdentity instanceof CredentialIdentity) {
            $containerBuilder->register(ConsoleBannerInterface::class, NullConsoleBanner::class);

            return;
        }

        $containerBuilder->register(ConsoleBannerInterface::class, CredentialConsoleBanner::class)
            ->setArguments([ContainerParameterSyntax::escape($credentialIdentity->maskedPreview)]);
    }

    /**
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     */
    private function selectActivePlatform(ContainerBuilder $containerBuilder, StandalonePlatformConfig $standalonePlatformConfig): void
    {
        $activeProvider = $standalonePlatformConfig->activeProvider;

        if (null !== $activeProvider) {
            $platformServiceId = \sprintf('%s%s', self::PLATFORM_SERVICE_PREFIX, $activeProvider);
            if (!$containerBuilder->hasDefinition($platformServiceId)) {
                throw $this->unknownProvider($containerBuilder, $activeProvider);
            }

            $containerBuilder->setAlias(PlatformInterface::class, $platformServiceId)->setPublic(true);

            return;
        }

        if (\count($containerBuilder->findTaggedServiceIds(self::PLATFORM_TAG)) > 1) {
            throw AmbiguousPlatformException::create();
        }
    }

    private function unknownProvider(ContainerBuilder $containerBuilder, string $activeProvider): UnknownPlatformProviderException
    {
        $providerKey = ProviderKey::of($activeProvider);
        $instances = $this->configuredInstancesOf($containerBuilder, $providerKey->platform);

        if ([] === $instances) {
            return UnknownPlatformProviderException::forProvider($activeProvider);
        }

        return null === $providerKey->instance
            ? UnknownPlatformProviderException::forInstanceKeyedProvider($providerKey->platform, $instances)
            : UnknownPlatformProviderException::forUnknownInstance($providerKey->platform, $providerKey->instance, $instances);
    }

    /**
     * @return list<string>
     */
    private function configuredInstancesOf(ContainerBuilder $containerBuilder, string $platform): array
    {
        $instances = [];

        foreach (array_keys($containerBuilder->findTaggedServiceIds(self::PLATFORM_TAG)) as $serviceId) {
            $providerKey = ProviderKey::of(substr($serviceId, \strlen(self::PLATFORM_SERVICE_PREFIX)));
            if ($platform === $providerKey->platform && null !== $providerKey->instance) {
                $instances[] = $providerKey->instance;
            }
        }

        return $instances;
    }
}
