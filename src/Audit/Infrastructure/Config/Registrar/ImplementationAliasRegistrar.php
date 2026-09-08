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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullTriageMemoryRecorder;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerFeedbackSnapshotInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\DeferredAdvisoryDatabase;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\FilesystemTriageMemoryStore;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Feedback\CompositeReviewerFeedbackProvider;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Feedback\ReviewerFeedbackHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;

/**
 * Points each port at the implementation the configuration selected.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ImplementationAliasRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->alias(AttackerCacheInterface::class, $bundleConfiguration->cache->enabled
            ? FilesystemAttackerCache::class
            : NullAttackerCache::class);

        $servicesConfigurator->alias(ReviewerCacheInterface::class, $bundleConfiguration->cache->enabled
            ? FilesystemReviewerCache::class
            : NullReviewerCache::class);

        $servicesConfigurator->alias(SecretScrubberInterface::class, $bundleConfiguration->scan->secretScrubbingEnabled
            ? RegexSecretScrubber::class
            : NullSecretScrubber::class);

        $servicesConfigurator->alias(AdvisoryDatabaseInterface::class, $bundleConfiguration->privacy->offlineOnly
            ? InMemoryAdvisoryDatabase::class
            : DeferredAdvisoryDatabase::class);

        $servicesConfigurator->alias(ComposerAuditRunnerInterface::class, $bundleConfiguration->cache->enabled
            ? LockfileHashedAdvisoryCache::class
            : SymfonyProcessComposerAuditRunner::class);

        $this->registerTriageMemory($servicesConfigurator, $bundleConfiguration);

        $servicesConfigurator->alias(CodeSlicerInterface::class, $bundleConfiguration->audit->codeSlicingEnabled
            ? RegexCodeSlicer::class
            : NullCodeSlicer::class);
    }

    /**
     * With `audit.triage_memory` enabled, the reviewer's own rejections persist
     * across runs and merge with any baseline-sourced feedback; disabled, the
     * feedback seam is the baseline-only behaviour of earlier releases.
     */
    private function registerTriageMemory(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        if (!$bundleConfiguration->audit->triageMemory) {
            $servicesConfigurator->alias(TriageMemoryRecorderInterface::class, NullTriageMemoryRecorder::class);
            $servicesConfigurator->alias(ReviewerFeedbackProviderInterface::class, ReviewerFeedbackHolder::class);

            return;
        }

        $servicesConfigurator->alias(TriageMemoryRecorderInterface::class, FilesystemTriageMemoryStore::class);
        $servicesConfigurator->alias(ReviewerFeedbackProviderInterface::class, CompositeReviewerFeedbackProvider::class);
        $servicesConfigurator->alias(ReviewerFeedbackSnapshotInterface::class, CompositeReviewerFeedbackProvider::class);
    }
}
