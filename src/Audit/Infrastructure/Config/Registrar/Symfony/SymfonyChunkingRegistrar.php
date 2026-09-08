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
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ChunkingVocabulary;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyChunkingVocabulary;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Teaches the chunker which Symfony surfaces the attacker should see first and
 * how a controller names the feature its entity, form, voter and templates
 * belong to. `FileChunker` itself is portable; only this vocabulary is not.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyChunkingRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(ChunkingVocabulary::class)
            ->factory([SymfonyChunkingVocabulary::class, 'create']);

        $servicesConfigurator->set(FileChunker::class)
            ->arg('$chunkingStrategy', inline_service(ChunkingStrategy::class)
                ->factory([ChunkingStrategy::class, 'from'])
                ->args([param('symfony_security_auditor.audit.chunking.strategy')]))
            ->arg('$chunkingVocabulary', service(ChunkingVocabulary::class));
    }
}
