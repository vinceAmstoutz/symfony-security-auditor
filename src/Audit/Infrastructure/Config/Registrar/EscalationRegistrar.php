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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar;

use Override;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AttackerAgentDefinitionFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\LlmClientDefinitionFactory;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class EscalationRegistrar implements ServiceRegistrarInterface
{
    public function __construct(
        private LlmClientDefinitionFactory $llmClientDefinitionFactory = new LlmClientDefinitionFactory(),
    ) {}

    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        if (!$bundleConfiguration->audit->escalationEnabled) {
            return;
        }

        $servicesConfigurator->set('security_auditor.cheap_attacker_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientDefinitionFactory->args(
                $bundleConfiguration,
                $bundleConfiguration->audit->effectiveEscalationCheapModel($bundleConfiguration->llm->reviewerModel()),
                $bundleConfiguration->llm->attackerMaxOutputTokens(),
            ));

        $this->registerCheapAttackerCache($servicesConfigurator, $bundleConfiguration);

        $servicesConfigurator->set('security_auditor.cheap_attacker', AttackerAgent::class)
            ->private()
            ->args((new AttackerAgentDefinitionFactory())->args(
                'security_auditor.cheap_attacker_client',
                'security_auditor.cheap_attacker_cache',
            ));

        $servicesConfigurator->set(EscalatingAttackerAgent::class)
            ->private()
            ->args([
                service('security_auditor.cheap_attacker'),
                service(AttackerAgent::class),
                service('logger'),
            ]);

        $servicesConfigurator->alias(AttackerAgentInterface::class, EscalatingAttackerAgent::class);
    }

    /**
     * The cheap attacker must never share cache entries with the primary
     * attacker: both would otherwise read and write the same keys, and a
     * cheap-model "no findings" result cached during an escalation run would
     * later be served to the full-price attacker as its own analysis.
     */
    private function registerCheapAttackerCache(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        if (!$bundleConfiguration->cache->enabled) {
            $servicesConfigurator->alias('security_auditor.cheap_attacker_cache', NullAttackerCache::class);

            return;
        }

        $servicesConfigurator->set('security_auditor.cheap_attacker_cache', FilesystemAttackerCache::class)
            ->private()
            ->args([
                param('symfony_security_auditor.cache.dir'),
                service(Filesystem::class),
                service('logger'),
                param('symfony_security_auditor.cache.cheap_attacker_key_salt'),
            ]);
    }
}
