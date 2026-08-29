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
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class RateLimiterRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(NullRateLimiter::class)->private();

        if (!$bundleConfiguration->rateLimit->isEnabled()) {
            $servicesConfigurator->alias(RateLimiterInterface::class, NullRateLimiter::class);

            return;
        }

        $servicesConfigurator->set(RateLimitConfiguration::class)
            ->private()
            ->args([
                $bundleConfiguration->rateLimit->requestsPerMinute,
                $bundleConfiguration->rateLimit->inputTokensPerMinute,
                $bundleConfiguration->rateLimit->outputTokensPerMinute,
            ]);
        $servicesConfigurator->set(TokenBucketRateLimiter::class)
            ->private()
            ->args([
                service(RateLimitConfiguration::class),
                service(ClockInterface::class),
                service(SleeperInterface::class),
            ]);
        $servicesConfigurator->alias(RateLimiterInterface::class, TokenBucketRateLimiter::class);
    }
}
