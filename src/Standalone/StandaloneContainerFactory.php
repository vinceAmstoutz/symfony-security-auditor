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
use RuntimeException;
use Symfony\AI\AiBundle\AiBundle;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FreeTextSettings;
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

        $containerBuilder = new ContainerBuilder(new EnvPlaceholderParameterBag($this->kernelParameters($cacheDir)));

        $containerBuilder->register('event_dispatcher', EventDispatcher::class)->setPublic(true);
        $containerBuilder->register('logger', NullLogger::class);
        $containerBuilder->register('http_client', HttpClientInterface::class)
            ->setFactory([HttpClient::class, 'create'])
            ->setArguments([$this->httpClientOptions($standaloneConfig)]);

        try {
            $this->bundleExtensionLoader->load(new AiBundle(), $standaloneConfig->platform->toAiConfig(), $containerBuilder);
        } catch (RuntimeException $runtimeException) {
            throw ProviderBridgeException::forBundleFailure($runtimeException) ?? $runtimeException;
        }

        $this->bundleExtensionLoader->load(new SymfonySecurityAuditorBundle(), FreeTextSettings::literalIn($standaloneConfig->auditConfig, $containerBuilder->getParameterBag()), $containerBuilder);

        $this->announceProjectConfigs($containerBuilder, $standaloneConfig);
        $this->registerAuditHeaderBanner($containerBuilder, $standaloneConfig->platform);

        $this->selectActivePlatform($containerBuilder, $standaloneConfig->platform);

        $containerBuilder->getDefinition(AuditCommand::class)->setPublic(true);
        $containerBuilder->getDefinition(McpServeCommand::class)->setPublic(true);
        $containerBuilder->addCompilerPass(new PricingPlatformPass(PlatformInterface::class));
        $containerBuilder->compile(true);

        return $containerBuilder;
    }

    /**
     * @return array<string, float|int|string>
     */
    private function httpClientOptions(StandaloneConfig $standaloneConfig): array
    {
        $options = ['timeout' => $standaloneConfig->httpTimeout, 'max_duration' => 0];

        return $standaloneConfig->offlineOnly() && $this->offlineOnlyPlatformGuard->reachesOnlyLoopback($standaloneConfig->platform)
            ? [...$options, 'no_proxy' => '*']
            : $options;
    }

    /**
     * The directories come from the user's home and the working directory, so
     * their `%` signs are escaped: left as typed, a pair reads as a parameter
     * reference, `%%` loses one sign and `%env(VAR)%` becomes the variable.
     *
     * @return array<string, bool|string>
     */
    private function kernelParameters(string $cacheDir): array
    {
        $escapedCacheDir = ContainerParameterSyntax::escape($cacheDir);
        $workingDirectory = getcwd();

        return [
            'kernel.cache_dir' => $escapedCacheDir,
            'kernel.build_dir' => $escapedCacheDir,
            'kernel.project_dir' => false !== $workingDirectory ? ContainerParameterSyntax::escape($workingDirectory) : $escapedCacheDir,
            'kernel.environment' => 'prod',
            'kernel.debug' => false,
        ];
    }

    private function announceProjectConfigs(ContainerBuilder $containerBuilder, StandaloneConfig $standaloneConfig): void
    {
        $projectConfigNotices = ProjectConfigNotices::of($standaloneConfig);
        if ([] === $projectConfigNotices) {
            return;
        }

        $notices = $containerBuilder->getParameter(self::CONFIG_NOTICES_PARAMETER);

        $containerBuilder->setParameter(self::CONFIG_NOTICES_PARAMETER, [
            ...(\is_array($notices) ? $notices : []),
            ...$projectConfigNotices,
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
