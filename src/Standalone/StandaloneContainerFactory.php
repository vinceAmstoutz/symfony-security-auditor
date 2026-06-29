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
use Symfony\AI\AiBundle\AiBundle;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use Symfony\Component\EventDispatcher\EventDispatcher;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneContainerFactory
{
    private const string PLATFORM_TAG = 'ai.platform';

    private const string PLATFORM_SERVICE_PREFIX = 'ai.platform.';

    /**
     * @var list<string>
     */
    private const array OVERRIDABLE_LLM_CLIENT_IDS = [
        'security_auditor.attacker_client',
        'security_auditor.reviewer_client',
    ];

    public function __construct(
        private BundleExtensionLoader $bundleExtensionLoader = new BundleExtensionLoader(),
    ) {}

    /**
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     */
    public function create(StandaloneConfig $standaloneConfig, string $cacheDir, ?LLMClientInterface $llmClient = null): ContainerBuilder
    {
        $workingDirectory = getcwd();

        $containerBuilder = new ContainerBuilder(new ParameterBag([
            'kernel.cache_dir' => $cacheDir,
            'kernel.build_dir' => $cacheDir,
            'kernel.project_dir' => false !== $workingDirectory ? $workingDirectory : $cacheDir,
            'kernel.environment' => 'prod',
            'kernel.debug' => false,
        ]));

        $containerBuilder->register('event_dispatcher', EventDispatcher::class)->setPublic(true);
        $containerBuilder->register('logger', NullLogger::class);

        $this->bundleExtensionLoader->load(new AiBundle(), $standaloneConfig->platform->toAiConfig(), $containerBuilder);
        $this->bundleExtensionLoader->load(new SymfonySecurityAuditorBundle(), $standaloneConfig->auditConfig, $containerBuilder);

        $this->selectActivePlatform($containerBuilder, $standaloneConfig->platform);
        $this->overrideLlmClient($containerBuilder, $llmClient);

        $containerBuilder->getDefinition(AuditCommand::class)->setPublic(true);
        $containerBuilder->compile();

        if ($llmClient instanceof LLMClientInterface) {
            foreach (self::OVERRIDABLE_LLM_CLIENT_IDS as $serviceId) {
                $containerBuilder->set($serviceId, $llmClient);
            }
        }

        return $containerBuilder;
    }

    private function overrideLlmClient(ContainerBuilder $containerBuilder, ?LLMClientInterface $llmClient): void
    {
        if (!$llmClient instanceof LLMClientInterface) {
            return;
        }

        foreach (self::OVERRIDABLE_LLM_CLIENT_IDS as $serviceId) {
            $containerBuilder->register($serviceId, LLMClientInterface::class)
                ->setSynthetic(true)
                ->setPublic(true);
        }
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
                throw UnknownPlatformProviderException::forProvider($activeProvider);
            }

            $containerBuilder->setAlias(PlatformInterface::class, $platformServiceId)->setPublic(true);

            return;
        }

        if (\count($containerBuilder->findTaggedServiceIds(self::PLATFORM_TAG)) > 1) {
            throw AmbiguousPlatformException::create();
        }
    }
}
