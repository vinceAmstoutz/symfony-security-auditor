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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Override;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

use function Symfony\Component\String\u;

/**
 * Publishes the `symfony/ai` platform the audit runs against, so pricing reads
 * that platform's own rates. `symfony/ai-bundle` aliases its platform
 * interface to `ai.platform.<platform>[.<instance>]` when a single platform is
 * configured, and the standalone binary does the same for its `provider`; the
 * composition root names that alias here, so this class touches no
 * `symfony/ai` type itself. A platform wired any other way leaves the
 * parameter null.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PricingPlatformPass implements CompilerPassInterface
{
    public const string PARAMETER = 'symfony_security_auditor.pricing.platform';

    private const string PLATFORM_SERVICE_PREFIX = 'ai.platform.';

    public function __construct(
        private string $platformAlias,
    ) {}

    #[Override]
    public function process(ContainerBuilder $container): void
    {
        $container->setParameter(self::PARAMETER, $this->servingPlatform($container));
    }

    private function servingPlatform(ContainerBuilder $containerBuilder): ?string
    {
        if (!$containerBuilder->hasAlias($this->platformAlias)) {
            return null;
        }

        $serviceId = u((string) $containerBuilder->getAlias($this->platformAlias));
        if (!$serviceId->startsWith(self::PLATFORM_SERVICE_PREFIX)) {
            return null;
        }

        return ProviderKey::of($serviceId->after(self::PLATFORM_SERVICE_PREFIX)->toString())->platform;
    }
}
