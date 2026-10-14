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

/**
 * Publishes the `symfony/ai` platforms an application configures when none is
 * selected for the audit: `symfony/ai-bundle` aliases its platform interface
 * only when a single platform is configured, so with several the audit has
 * no platform until the application aliases the interface to one of them.
 * The composition root names that interface here, so this class touches no
 * `symfony/ai` type itself.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class UnselectedPlatformsPass implements CompilerPassInterface
{
    public const string PARAMETER = 'symfony_security_auditor.unselected_platforms';

    private const string PLATFORM_TAG = 'ai.platform';

    private const int SEVERAL = 2;

    public function __construct(
        private string $platformAlias,
    ) {}

    #[Override]
    public function process(ContainerBuilder $container): void
    {
        $container->setParameter(self::PARAMETER, $this->unselectedPlatforms($container));
    }

    /**
     * @return list<string>
     */
    private function unselectedPlatforms(ContainerBuilder $containerBuilder): array
    {
        $platforms = array_keys($containerBuilder->findTaggedServiceIds(self::PLATFORM_TAG));

        return $containerBuilder->has($this->platformAlias) || \count($platforms) < self::SEVERAL ? [] : $platforms;
    }
}
