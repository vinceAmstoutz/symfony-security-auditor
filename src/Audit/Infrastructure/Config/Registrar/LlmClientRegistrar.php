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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\LlmClientDefinitionFactory;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class LlmClientRegistrar implements ServiceRegistrarInterface
{
    public function __construct(
        private LlmClientDefinitionFactory $llmClientDefinitionFactory = new LlmClientDefinitionFactory(),
    ) {}

    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(RetryAfterHeaderParser::class)->private();

        $servicesConfigurator->set('security_auditor.attacker_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientDefinitionFactory->args(
                $bundleConfiguration,
                $bundleConfiguration->llm->attackerModel(),
                $bundleConfiguration->llm->attackerMaxOutputTokens(),
            ));

        $servicesConfigurator->set('security_auditor.reviewer_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientDefinitionFactory->args(
                $bundleConfiguration,
                $bundleConfiguration->llm->reviewerModel(),
                $bundleConfiguration->llm->reviewerMaxOutputTokens(),
            ));

        $servicesConfigurator->alias(LLMClientInterface::class, 'security_auditor.attacker_client');
    }
}
