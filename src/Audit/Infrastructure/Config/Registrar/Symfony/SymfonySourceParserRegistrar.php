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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony;

use Override;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AccessControlConfigParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AuthorizationRuleParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\EntrypointAccessControlParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * The deterministic extractions that read Symfony attributes and `security.yaml`
 * to build the application security map.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonySourceParserRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(PhpParserControllerAccessControlParser::class);
        $servicesConfigurator->alias(EntrypointAccessControlParserInterface::class, PhpParserControllerAccessControlParser::class);

        $servicesConfigurator->set(PhpParserVoterCapabilityParser::class);
        $servicesConfigurator->alias(AuthorizationRuleParserInterface::class, PhpParserVoterCapabilityParser::class);

        $servicesConfigurator->set(PhpParserFormBindingParser::class);
        $servicesConfigurator->alias(FormBindingParserInterface::class, PhpParserFormBindingParser::class);

        $servicesConfigurator->set(SymfonyYamlSecurityConfigParser::class)
            ->args([service('logger')]);
        $servicesConfigurator->alias(AccessControlConfigParserInterface::class, SymfonyYamlSecurityConfigParser::class);
    }
}
